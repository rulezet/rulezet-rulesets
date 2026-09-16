rule TTP_XOR_WriteProcessMemory_b680 {
  strings:
    $key_b680 = { e1 f2 [2] d3 d0 [2] d5 e5 [2] fb e5 [2] c4 f9 }

  condition:
    any of them
}