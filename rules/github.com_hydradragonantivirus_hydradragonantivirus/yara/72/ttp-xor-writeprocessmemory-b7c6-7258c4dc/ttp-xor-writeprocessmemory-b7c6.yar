rule TTP_XOR_WriteProcessMemory_b7c6 {
  strings:
    $key_b7c6 = { e0 b4 [2] d2 96 [2] d4 a3 [2] fa a3 [2] c5 bf }

  condition:
    any of them
}