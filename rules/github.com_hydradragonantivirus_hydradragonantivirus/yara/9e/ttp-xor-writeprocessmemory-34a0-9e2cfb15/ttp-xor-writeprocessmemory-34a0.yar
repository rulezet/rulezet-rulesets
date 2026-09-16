rule TTP_XOR_WriteProcessMemory_34a0 {
  strings:
    $key_34a0 = { 63 d2 [2] 51 f0 [2] 57 c5 [2] 79 c5 [2] 46 d9 }

  condition:
    any of them
}