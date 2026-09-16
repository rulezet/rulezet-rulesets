rule TTP_XOR_WriteProcessMemory_b09b {
  strings:
    $key_b09b = { e7 e9 [2] d5 cb [2] d3 fe [2] fd fe [2] c2 e2 }

  condition:
    any of them
}