rule TTP_XOR_WriteProcessMemory_b5c6 {
  strings:
    $key_b5c6 = { e2 b4 [2] d0 96 [2] d6 a3 [2] f8 a3 [2] c7 bf }

  condition:
    any of them
}