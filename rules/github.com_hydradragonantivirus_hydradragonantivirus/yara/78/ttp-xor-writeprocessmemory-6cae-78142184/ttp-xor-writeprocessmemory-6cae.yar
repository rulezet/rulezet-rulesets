rule TTP_XOR_WriteProcessMemory_6cae {
  strings:
    $key_6cae = { 3b dc [2] 09 fe [2] 0f cb [2] 21 cb [2] 1e d7 }

  condition:
    any of them
}