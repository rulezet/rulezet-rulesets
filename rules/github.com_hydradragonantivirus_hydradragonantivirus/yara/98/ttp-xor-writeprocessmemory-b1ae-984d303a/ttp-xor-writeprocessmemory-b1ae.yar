rule TTP_XOR_WriteProcessMemory_b1ae {
  strings:
    $key_b1ae = { e6 dc [2] d4 fe [2] d2 cb [2] fc cb [2] c3 d7 }

  condition:
    any of them
}