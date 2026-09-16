rule TTP_XOR_WriteProcessMemory_f7e5 {
  strings:
    $key_f7e5 = { a0 97 [2] 92 b5 [2] 94 80 [2] ba 80 [2] 85 9c }

  condition:
    any of them
}