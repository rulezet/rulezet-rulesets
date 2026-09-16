rule TTP_XOR_WriteProcessMemory_b69b {
  strings:
    $key_b69b = { e1 e9 [2] d3 cb [2] d5 fe [2] fb fe [2] c4 e2 }

  condition:
    any of them
}