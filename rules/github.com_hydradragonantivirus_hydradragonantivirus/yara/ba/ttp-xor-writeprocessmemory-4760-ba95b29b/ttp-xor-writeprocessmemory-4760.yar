rule TTP_XOR_WriteProcessMemory_4760 {
  strings:
    $key_4760 = { 10 12 [2] 22 30 [2] 24 05 [2] 0a 05 [2] 35 19 }

  condition:
    any of them
}