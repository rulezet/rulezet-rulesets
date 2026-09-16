rule TTP_XOR_WriteProcessMemory_25ae {
  strings:
    $key_25ae = { 72 dc [2] 40 fe [2] 46 cb [2] 68 cb [2] 57 d7 }

  condition:
    any of them
}