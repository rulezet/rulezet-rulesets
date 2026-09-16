rule TTP_XOR_WriteProcessMemory_3cae {
  strings:
    $key_3cae = { 6b dc [2] 59 fe [2] 5f cb [2] 71 cb [2] 4e d7 }

  condition:
    any of them
}