rule TTP_XOR_WriteProcessMemory_8cae {
  strings:
    $key_8cae = { db dc [2] e9 fe [2] ef cb [2] c1 cb [2] fe d7 }

  condition:
    any of them
}