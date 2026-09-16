rule TTP_XOR_WriteProcessMemory_7721 {
  strings:
    $key_7721 = { 20 53 [2] 12 71 [2] 14 44 [2] 3a 44 [2] 05 58 }

  condition:
    any of them
}