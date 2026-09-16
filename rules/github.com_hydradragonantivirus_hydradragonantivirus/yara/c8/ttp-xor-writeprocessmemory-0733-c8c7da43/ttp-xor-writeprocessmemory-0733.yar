rule TTP_XOR_WriteProcessMemory_0733 {
  strings:
    $key_0733 = { 50 41 [2] 62 63 [2] 64 56 [2] 4a 56 [2] 75 4a }

  condition:
    any of them
}