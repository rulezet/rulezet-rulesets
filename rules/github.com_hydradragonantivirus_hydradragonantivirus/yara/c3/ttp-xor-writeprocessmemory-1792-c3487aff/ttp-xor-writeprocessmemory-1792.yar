rule TTP_XOR_WriteProcessMemory_1792 {
  strings:
    $key_1792 = { 40 e0 [2] 72 c2 [2] 74 f7 [2] 5a f7 [2] 65 eb }

  condition:
    any of them
}