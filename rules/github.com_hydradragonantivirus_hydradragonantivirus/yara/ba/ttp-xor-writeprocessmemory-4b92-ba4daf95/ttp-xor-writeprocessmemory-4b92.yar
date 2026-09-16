rule TTP_XOR_WriteProcessMemory_4b92 {
  strings:
    $key_4b92 = { 1c e0 [2] 2e c2 [2] 28 f7 [2] 06 f7 [2] 39 eb }

  condition:
    any of them
}