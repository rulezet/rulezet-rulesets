rule TTP_XOR_WriteProcessMemory_b695 {
  strings:
    $key_b695 = { e1 e7 [2] d3 c5 [2] d5 f0 [2] fb f0 [2] c4 ec }

  condition:
    any of them
}