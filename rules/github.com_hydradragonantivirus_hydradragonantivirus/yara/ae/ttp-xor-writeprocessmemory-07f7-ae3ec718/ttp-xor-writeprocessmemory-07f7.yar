rule TTP_XOR_WriteProcessMemory_07f7 {
  strings:
    $key_07f7 = { 50 85 [2] 62 a7 [2] 64 92 [2] 4a 92 [2] 75 8e }

  condition:
    any of them
}