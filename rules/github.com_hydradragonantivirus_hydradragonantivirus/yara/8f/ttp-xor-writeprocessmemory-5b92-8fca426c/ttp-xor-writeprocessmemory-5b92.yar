rule TTP_XOR_WriteProcessMemory_5b92 {
  strings:
    $key_5b92 = { 0c e0 [2] 3e c2 [2] 38 f7 [2] 16 f7 [2] 29 eb }

  condition:
    any of them
}