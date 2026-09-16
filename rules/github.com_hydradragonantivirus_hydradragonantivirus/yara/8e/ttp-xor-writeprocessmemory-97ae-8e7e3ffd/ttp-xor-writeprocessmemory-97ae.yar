rule TTP_XOR_WriteProcessMemory_97ae {
  strings:
    $key_97ae = { c0 dc [2] f2 fe [2] f4 cb [2] da cb [2] e5 d7 }

  condition:
    any of them
}