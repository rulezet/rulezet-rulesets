rule TTP_XOR_WriteProcessMemory_b2c6 {
  strings:
    $key_b2c6 = { e5 b4 [2] d7 96 [2] d1 a3 [2] ff a3 [2] c0 bf }

  condition:
    any of them
}