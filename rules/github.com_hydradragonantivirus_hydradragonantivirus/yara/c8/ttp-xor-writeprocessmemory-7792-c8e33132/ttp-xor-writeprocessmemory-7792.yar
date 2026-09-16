rule TTP_XOR_WriteProcessMemory_7792 {
  strings:
    $key_7792 = { 20 e0 [2] 12 c2 [2] 14 f7 [2] 3a f7 [2] 05 eb }

  condition:
    any of them
}