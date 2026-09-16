rule TTP_XOR_WriteProcessMemory_739c {
  strings:
    $key_739c = { 24 ee [2] 16 cc [2] 10 f9 [2] 3e f9 [2] 01 e5 }

  condition:
    any of them
}