rule TTP_XOR_WriteProcessMemory_0743 {
  strings:
    $key_0743 = { 50 31 [2] 62 13 [2] 64 26 [2] 4a 26 [2] 75 3a }

  condition:
    any of them
}