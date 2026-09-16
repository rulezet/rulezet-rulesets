rule TTP_XOR_WriteProcessMemory_b0ae {
  strings:
    $key_b0ae = { e7 dc [2] d5 fe [2] d3 cb [2] fd cb [2] c2 d7 }

  condition:
    any of them
}