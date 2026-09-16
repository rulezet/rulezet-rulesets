rule TTP_XOR_WriteProcessMemory_0713 {
  strings:
    $key_0713 = { 50 61 [2] 62 43 [2] 64 76 [2] 4a 76 [2] 75 6a }

  condition:
    any of them
}