rule TTP_XOR_WriteProcessMemory_5cae {
  strings:
    $key_5cae = { 0b dc [2] 39 fe [2] 3f cb [2] 11 cb [2] 2e d7 }

  condition:
    any of them
}