rule TTP_XOR_WriteProcessMemory_e972 {
  strings:
    $key_e972 = { be 00 [2] 8c 22 [2] 8a 17 [2] a4 17 [2] 9b 0b }

  condition:
    any of them
}