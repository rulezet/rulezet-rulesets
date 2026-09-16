rule TTP_XOR_WriteProcessMemory_6354 {
  strings:
    $key_6354 = { 34 26 [2] 06 04 [2] 00 31 [2] 2e 31 [2] 11 2d }

  condition:
    any of them
}