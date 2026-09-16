rule TTP_XOR_WriteProcessMemory_4793 {
  strings:
    $key_4793 = { 10 e1 [2] 22 c3 [2] 24 f6 [2] 0a f6 [2] 35 ea }

  condition:
    any of them
}