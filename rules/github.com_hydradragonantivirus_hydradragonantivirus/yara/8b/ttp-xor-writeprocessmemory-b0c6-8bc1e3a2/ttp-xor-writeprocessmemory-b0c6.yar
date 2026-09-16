rule TTP_XOR_WriteProcessMemory_b0c6 {
  strings:
    $key_b0c6 = { e7 b4 [2] d5 96 [2] d3 a3 [2] fd a3 [2] c2 bf }

  condition:
    any of them
}