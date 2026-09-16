rule TTP_XOR_WriteProcessMemory_b3c4 {
  strings:
    $key_b3c4 = { e4 b6 [2] d6 94 [2] d0 a1 [2] fe a1 [2] c1 bd }

  condition:
    any of them
}