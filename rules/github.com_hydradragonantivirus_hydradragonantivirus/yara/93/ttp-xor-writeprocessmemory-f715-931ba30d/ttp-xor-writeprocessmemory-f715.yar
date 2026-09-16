rule TTP_XOR_WriteProcessMemory_f715 {
  strings:
    $key_f715 = { a0 67 [2] 92 45 [2] 94 70 [2] ba 70 [2] 85 6c }

  condition:
    any of them
}