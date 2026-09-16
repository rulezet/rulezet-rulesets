rule TTP_XOR_WriteProcessMemory_17f7 {
  strings:
    $key_17f7 = { 40 85 [2] 72 a7 [2] 74 92 [2] 5a 92 [2] 65 8e }

  condition:
    any of them
}