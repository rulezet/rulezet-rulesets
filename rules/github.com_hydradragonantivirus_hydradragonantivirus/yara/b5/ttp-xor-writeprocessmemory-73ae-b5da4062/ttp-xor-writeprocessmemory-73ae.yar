rule TTP_XOR_WriteProcessMemory_73ae {
  strings:
    $key_73ae = { 24 dc [2] 16 fe [2] 10 cb [2] 3e cb [2] 01 d7 }

  condition:
    any of them
}