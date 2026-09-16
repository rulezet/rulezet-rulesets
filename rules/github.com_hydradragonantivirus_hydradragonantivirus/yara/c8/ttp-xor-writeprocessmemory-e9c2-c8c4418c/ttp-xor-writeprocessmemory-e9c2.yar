rule TTP_XOR_WriteProcessMemory_e9c2 {
  strings:
    $key_e9c2 = { be b0 [2] 8c 92 [2] 8a a7 [2] a4 a7 [2] 9b bb }

  condition:
    any of them
}