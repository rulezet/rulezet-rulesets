rule TTP_XOR_WriteProcessMemory_0756 {
  strings:
    $key_0756 = { 50 24 [2] 62 06 [2] 64 33 [2] 4a 33 [2] 75 2f }

  condition:
    any of them
}