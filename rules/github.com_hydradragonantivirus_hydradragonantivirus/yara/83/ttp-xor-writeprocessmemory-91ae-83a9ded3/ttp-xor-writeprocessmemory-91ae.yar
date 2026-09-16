rule TTP_XOR_WriteProcessMemory_91ae {
  strings:
    $key_91ae = { c6 dc [2] f4 fe [2] f2 cb [2] dc cb [2] e3 d7 }

  condition:
    any of them
}