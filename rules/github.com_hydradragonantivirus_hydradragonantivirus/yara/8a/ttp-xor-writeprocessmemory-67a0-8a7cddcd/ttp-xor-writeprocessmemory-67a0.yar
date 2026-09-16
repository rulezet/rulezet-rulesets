rule TTP_XOR_WriteProcessMemory_67a0 {
  strings:
    $key_67a0 = { 30 d2 [2] 02 f0 [2] 04 c5 [2] 2a c5 [2] 15 d9 }

  condition:
    any of them
}