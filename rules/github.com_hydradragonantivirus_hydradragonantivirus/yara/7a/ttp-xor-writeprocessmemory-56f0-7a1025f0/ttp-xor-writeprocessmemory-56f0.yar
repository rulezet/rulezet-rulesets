rule TTP_XOR_WriteProcessMemory_56f0 {
  strings:
    $key_56f0 = { 01 82 [2] 33 a0 [2] 35 95 [2] 1b 95 [2] 24 89 }

  condition:
    any of them
}