rule TTP_XOR_WriteProcessMemory_1a42 {
  strings:
    $key_1a42 = { 4d 30 [2] 7f 12 [2] 79 27 [2] 57 27 [2] 68 3b }

  condition:
    any of them
}