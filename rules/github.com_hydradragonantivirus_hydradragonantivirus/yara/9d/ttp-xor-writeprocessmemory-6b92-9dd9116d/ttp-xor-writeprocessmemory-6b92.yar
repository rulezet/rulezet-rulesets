rule TTP_XOR_WriteProcessMemory_6b92 {
  strings:
    $key_6b92 = { 3c e0 [2] 0e c2 [2] 08 f7 [2] 26 f7 [2] 19 eb }

  condition:
    any of them
}