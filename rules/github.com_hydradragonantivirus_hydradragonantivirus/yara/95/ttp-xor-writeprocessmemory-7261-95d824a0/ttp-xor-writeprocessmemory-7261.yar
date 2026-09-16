rule TTP_XOR_WriteProcessMemory_7261 {
  strings:
    $key_7261 = { 25 13 [2] 17 31 [2] 11 04 [2] 3f 04 [2] 00 18 }

  condition:
    any of them
}