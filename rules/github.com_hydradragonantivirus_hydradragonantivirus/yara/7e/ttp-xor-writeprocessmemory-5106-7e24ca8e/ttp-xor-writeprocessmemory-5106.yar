rule TTP_XOR_WriteProcessMemory_5106 {
  strings:
    $key_5106 = { 06 74 [2] 34 56 [2] 32 63 [2] 1c 63 [2] 23 7f }

  condition:
    any of them
}