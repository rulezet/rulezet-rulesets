rule TTP_XOR_WriteProcessMemory_77ae {
  strings:
    $key_77ae = { 20 dc [2] 12 fe [2] 14 cb [2] 3a cb [2] 05 d7 }

  condition:
    any of them
}