rule TTP_XOR_WriteProcessMemory_12f7 {
  strings:
    $key_12f7 = { 45 85 [2] 77 a7 [2] 71 92 [2] 5f 92 [2] 60 8e }

  condition:
    any of them
}