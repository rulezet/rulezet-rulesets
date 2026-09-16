rule TTP_XOR_WriteProcessMemory_0726 {
  strings:
    $key_0726 = { 50 54 [2] 62 76 [2] 64 43 [2] 4a 43 [2] 75 5f }

  condition:
    any of them
}