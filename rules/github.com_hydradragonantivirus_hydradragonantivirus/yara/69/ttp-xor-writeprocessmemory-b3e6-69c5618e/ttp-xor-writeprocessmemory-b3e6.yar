rule TTP_XOR_WriteProcessMemory_b3e6 {
  strings:
    $key_b3e6 = { e4 94 [2] d6 b6 [2] d0 83 [2] fe 83 [2] c1 9f }

  condition:
    any of them
}