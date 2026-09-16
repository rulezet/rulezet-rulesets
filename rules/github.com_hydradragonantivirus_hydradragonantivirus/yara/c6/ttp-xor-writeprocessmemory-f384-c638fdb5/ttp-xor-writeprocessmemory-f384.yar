rule TTP_XOR_WriteProcessMemory_f384 {
  strings:
    $key_f384 = { a4 f6 [2] 96 d4 [2] 90 e1 [2] be e1 [2] 81 fd }

  condition:
    any of them
}