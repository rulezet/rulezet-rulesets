rule TTP_XOR_WriteProcessMemory_b6c6 {
  strings:
    $key_b6c6 = { e1 b4 [2] d3 96 [2] d5 a3 [2] fb a3 [2] c4 bf }

  condition:
    any of them
}