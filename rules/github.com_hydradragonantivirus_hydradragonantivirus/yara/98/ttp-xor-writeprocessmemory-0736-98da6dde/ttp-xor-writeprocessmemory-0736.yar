rule TTP_XOR_WriteProcessMemory_0736 {
  strings:
    $key_0736 = { 50 44 [2] 62 66 [2] 64 53 [2] 4a 53 [2] 75 4f }

  condition:
    any of them
}