rule TTP_XOR_WriteProcessMemory_1340 {
  strings:
    $key_1340 = { 44 32 [2] 76 10 [2] 70 25 [2] 5e 25 [2] 61 39 }

  condition:
    any of them
}