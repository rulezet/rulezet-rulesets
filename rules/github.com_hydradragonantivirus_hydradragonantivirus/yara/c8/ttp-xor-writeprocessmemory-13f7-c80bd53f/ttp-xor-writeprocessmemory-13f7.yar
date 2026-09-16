rule TTP_XOR_WriteProcessMemory_13f7 {
  strings:
    $key_13f7 = { 44 85 [2] 76 a7 [2] 70 92 [2] 5e 92 [2] 61 8e }

  condition:
    any of them
}