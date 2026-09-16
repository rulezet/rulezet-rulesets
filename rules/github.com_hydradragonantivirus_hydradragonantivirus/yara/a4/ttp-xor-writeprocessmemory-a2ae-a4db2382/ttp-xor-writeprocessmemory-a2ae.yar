rule TTP_XOR_WriteProcessMemory_a2ae {
  strings:
    $key_a2ae = { f5 dc [2] c7 fe [2] c1 cb [2] ef cb [2] d0 d7 }

  condition:
    any of them
}