rule TTP_XOR_WriteProcessMemory_b08c {
  strings:
    $key_b08c = { e7 fe [2] d5 dc [2] d3 e9 [2] fd e9 [2] c2 f5 }

  condition:
    any of them
}