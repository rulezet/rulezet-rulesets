rule TTP_XOR_WriteProcessMemory_1a71 {
  strings:
    $key_1a71 = { 4d 03 [2] 7f 21 [2] 79 14 [2] 57 14 [2] 68 08 }

  condition:
    any of them
}