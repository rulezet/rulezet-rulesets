rule TTP_XOR_WriteProcessMemory_6321 {
  strings:
    $key_6321 = { 34 53 [2] 06 71 [2] 00 44 [2] 2e 44 [2] 11 58 }

  condition:
    any of them
}