rule TTP_XOR_WriteProcessMemory_b3ae {
  strings:
    $key_b3ae = { e4 dc [2] d6 fe [2] d0 cb [2] fe cb [2] c1 d7 }

  condition:
    any of them
}