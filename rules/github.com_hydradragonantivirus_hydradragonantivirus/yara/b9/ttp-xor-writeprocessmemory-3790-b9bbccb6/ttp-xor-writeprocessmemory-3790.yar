rule TTP_XOR_WriteProcessMemory_3790 {
  strings:
    $key_3790 = { 60 e2 [2] 52 c0 [2] 54 f5 [2] 7a f5 [2] 45 e9 }

  condition:
    any of them
}