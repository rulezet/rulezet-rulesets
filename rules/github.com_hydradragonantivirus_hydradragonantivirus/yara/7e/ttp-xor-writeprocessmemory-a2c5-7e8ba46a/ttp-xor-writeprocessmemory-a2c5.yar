rule TTP_XOR_WriteProcessMemory_a2c5 {
  strings:
    $key_a2c5 = { f5 b7 [2] c7 95 [2] c1 a0 [2] ef a0 [2] d0 bc }

  condition:
    any of them
}