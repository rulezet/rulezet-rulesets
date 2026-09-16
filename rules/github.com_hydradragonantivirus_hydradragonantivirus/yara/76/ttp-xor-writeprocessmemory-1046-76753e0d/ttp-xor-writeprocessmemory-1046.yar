rule TTP_XOR_WriteProcessMemory_1046 {
  strings:
    $key_1046 = { 47 34 [2] 75 16 [2] 73 23 [2] 5d 23 [2] 62 3f }

  condition:
    any of them
}