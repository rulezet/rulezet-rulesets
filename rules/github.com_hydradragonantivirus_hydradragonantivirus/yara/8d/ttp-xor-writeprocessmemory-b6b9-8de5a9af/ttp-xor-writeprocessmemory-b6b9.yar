rule TTP_XOR_WriteProcessMemory_b6b9 {
  strings:
    $key_b6b9 = { e1 cb [2] d3 e9 [2] d5 dc [2] fb dc [2] c4 c0 }

  condition:
    any of them
}