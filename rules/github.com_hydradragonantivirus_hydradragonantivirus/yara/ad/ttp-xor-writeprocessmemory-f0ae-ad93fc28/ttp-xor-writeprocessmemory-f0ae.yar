rule TTP_XOR_WriteProcessMemory_f0ae {
  strings:
    $key_f0ae = { a7 dc [2] 95 fe [2] 93 cb [2] bd cb [2] 82 d7 }

  condition:
    any of them
}