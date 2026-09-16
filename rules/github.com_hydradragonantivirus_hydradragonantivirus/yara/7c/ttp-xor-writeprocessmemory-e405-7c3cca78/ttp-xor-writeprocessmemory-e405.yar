rule TTP_XOR_WriteProcessMemory_e405 {
  strings:
    $key_e405 = { b3 77 [2] 81 55 [2] 87 60 [2] a9 60 [2] 96 7c }

  condition:
    any of them
}