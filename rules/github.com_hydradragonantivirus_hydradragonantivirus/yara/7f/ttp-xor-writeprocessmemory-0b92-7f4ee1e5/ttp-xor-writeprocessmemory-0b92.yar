rule TTP_XOR_WriteProcessMemory_0b92 {
  strings:
    $key_0b92 = { 5c e0 [2] 6e c2 [2] 68 f7 [2] 46 f7 [2] 79 eb }

  condition:
    any of them
}