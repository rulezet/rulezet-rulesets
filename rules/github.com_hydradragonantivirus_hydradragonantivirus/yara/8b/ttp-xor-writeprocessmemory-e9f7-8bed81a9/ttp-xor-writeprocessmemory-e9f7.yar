rule TTP_XOR_WriteProcessMemory_e9f7 {
  strings:
    $key_e9f7 = { be 85 [2] 8c a7 [2] 8a 92 [2] a4 92 [2] 9b 8e }

  condition:
    any of them
}