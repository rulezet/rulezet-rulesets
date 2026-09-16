rule TTP_XOR_WriteProcessMemory_46f7 {
  strings:
    $key_46f7 = { 11 85 [2] 23 a7 [2] 25 92 [2] 0b 92 [2] 34 8e }

  condition:
    any of them
}