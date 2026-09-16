rule TTP_XOR_WriteProcessMemory_7797 {
  strings:
    $key_7797 = { 20 e5 [2] 12 c7 [2] 14 f2 [2] 3a f2 [2] 05 ee }

  condition:
    any of them
}