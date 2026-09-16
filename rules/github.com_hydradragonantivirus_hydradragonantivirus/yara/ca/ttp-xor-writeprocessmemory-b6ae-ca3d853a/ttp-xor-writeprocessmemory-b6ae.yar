rule TTP_XOR_WriteProcessMemory_b6ae {
  strings:
    $key_b6ae = { e1 dc [2] d3 fe [2] d5 cb [2] fb cb [2] c4 d7 }

  condition:
    any of them
}