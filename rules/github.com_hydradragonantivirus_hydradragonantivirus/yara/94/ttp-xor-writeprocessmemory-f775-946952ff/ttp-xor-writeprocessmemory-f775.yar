rule TTP_XOR_WriteProcessMemory_f775 {
  strings:
    $key_f775 = { a0 07 [2] 92 25 [2] 94 10 [2] ba 10 [2] 85 0c }

  condition:
    any of them
}