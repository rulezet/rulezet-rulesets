rule TTP_XOR_WriteProcessMemory_b1c6 {
  strings:
    $key_b1c6 = { e6 b4 [2] d4 96 [2] d2 a3 [2] fc a3 [2] c3 bf }

  condition:
    any of them
}