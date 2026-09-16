rule TTP_XOR_WriteProcessMemory_d8ae {
  strings:
    $key_d8ae = { 8f dc [2] bd fe [2] bb cb [2] 95 cb [2] aa d7 }

  condition:
    any of them
}