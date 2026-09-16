rule TTP_XOR_WriteProcessMemory_a4ae {
  strings:
    $key_a4ae = { f3 dc [2] c1 fe [2] c7 cb [2] e9 cb [2] d6 d7 }

  condition:
    any of them
}