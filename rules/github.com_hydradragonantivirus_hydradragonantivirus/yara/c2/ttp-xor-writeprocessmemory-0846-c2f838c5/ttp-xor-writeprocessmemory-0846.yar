rule TTP_XOR_WriteProcessMemory_0846 {
  strings:
    $key_0846 = { 5f 34 [2] 6d 16 [2] 6b 23 [2] 45 23 [2] 7a 3f }

  condition:
    any of them
}