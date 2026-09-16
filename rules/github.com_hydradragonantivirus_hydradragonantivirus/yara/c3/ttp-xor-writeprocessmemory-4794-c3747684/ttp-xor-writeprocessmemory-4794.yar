rule TTP_XOR_WriteProcessMemory_4794 {
  strings:
    $key_4794 = { 10 e6 [2] 22 c4 [2] 24 f1 [2] 0a f1 [2] 35 ed }

  condition:
    any of them
}