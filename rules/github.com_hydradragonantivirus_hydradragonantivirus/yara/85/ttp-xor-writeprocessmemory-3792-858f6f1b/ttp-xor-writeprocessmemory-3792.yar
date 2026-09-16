rule TTP_XOR_WriteProcessMemory_3792 {
  strings:
    $key_3792 = { 60 e0 [2] 52 c2 [2] 54 f7 [2] 7a f7 [2] 45 eb }

  condition:
    any of them
}