rule TTP_XOR_WriteProcessMemory_92ae {
  strings:
    $key_92ae = { c5 dc [2] f7 fe [2] f1 cb [2] df cb [2] e0 d7 }

  condition:
    any of them
}