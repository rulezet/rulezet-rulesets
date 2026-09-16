rule TTP_XOR_WriteProcessMemory_8cd9 {
  strings:
    $key_8cd9 = { db ab [2] e9 89 [2] ef bc [2] c1 bc [2] fe a0 }

  condition:
    any of them
}