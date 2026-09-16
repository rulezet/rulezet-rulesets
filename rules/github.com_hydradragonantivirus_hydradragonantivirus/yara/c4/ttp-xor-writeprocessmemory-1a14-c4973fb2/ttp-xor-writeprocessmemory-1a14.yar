rule TTP_XOR_WriteProcessMemory_1a14 {
  strings:
    $key_1a14 = { 4d 66 [2] 7f 44 [2] 79 71 [2] 57 71 [2] 68 6d }

  condition:
    any of them
}