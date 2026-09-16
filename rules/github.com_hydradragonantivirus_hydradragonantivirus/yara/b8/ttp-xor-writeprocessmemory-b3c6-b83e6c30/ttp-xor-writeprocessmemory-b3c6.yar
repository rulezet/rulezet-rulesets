rule TTP_XOR_WriteProcessMemory_b3c6 {
  strings:
    $key_b3c6 = { e4 b4 [2] d6 96 [2] d0 a3 [2] fe a3 [2] c1 bf }

  condition:
    any of them
}