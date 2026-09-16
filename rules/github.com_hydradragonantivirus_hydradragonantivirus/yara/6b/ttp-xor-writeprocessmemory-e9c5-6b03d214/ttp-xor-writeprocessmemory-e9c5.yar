rule TTP_XOR_WriteProcessMemory_e9c5 {
  strings:
    $key_e9c5 = { be b7 [2] 8c 95 [2] 8a a0 [2] a4 a0 [2] 9b bc }

  condition:
    any of them
}