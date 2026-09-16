rule TTP_XOR_WriteProcessMemory_b3e4 {
  strings:
    $key_b3e4 = { e4 96 [2] d6 b4 [2] d0 81 [2] fe 81 [2] c1 9d }

  condition:
    any of them
}