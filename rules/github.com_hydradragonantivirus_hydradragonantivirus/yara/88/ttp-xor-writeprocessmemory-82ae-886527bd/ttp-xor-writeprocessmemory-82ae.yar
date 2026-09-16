rule TTP_XOR_WriteProcessMemory_82ae {
  strings:
    $key_82ae = { d5 dc [2] e7 fe [2] e1 cb [2] cf cb [2] f0 d7 }

  condition:
    any of them
}