rule TTP_XOR_WriteProcessMemory_beae {
  strings:
    $key_beae = { e9 dc [2] db fe [2] dd cb [2] f3 cb [2] cc d7 }

  condition:
    any of them
}