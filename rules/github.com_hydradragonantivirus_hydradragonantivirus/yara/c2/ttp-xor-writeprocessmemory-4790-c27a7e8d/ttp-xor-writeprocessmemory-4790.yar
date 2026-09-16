rule TTP_XOR_WriteProcessMemory_4790 {
  strings:
    $key_4790 = { 10 e2 [2] 22 c0 [2] 24 f5 [2] 0a f5 [2] 35 e9 }

  condition:
    any of them
}