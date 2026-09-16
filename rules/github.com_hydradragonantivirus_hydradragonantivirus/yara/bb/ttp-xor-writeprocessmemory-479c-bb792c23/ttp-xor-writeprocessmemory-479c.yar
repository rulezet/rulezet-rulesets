rule TTP_XOR_WriteProcessMemory_479c {
  strings:
    $key_479c = { 10 ee [2] 22 cc [2] 24 f9 [2] 0a f9 [2] 35 e5 }

  condition:
    any of them
}