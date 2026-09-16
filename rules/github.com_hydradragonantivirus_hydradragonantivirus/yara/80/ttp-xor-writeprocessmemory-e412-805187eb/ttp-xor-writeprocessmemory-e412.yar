rule TTP_XOR_WriteProcessMemory_e412 {
  strings:
    $key_e412 = { b3 60 [2] 81 42 [2] 87 77 [2] a9 77 [2] 96 6b }

  condition:
    any of them
}