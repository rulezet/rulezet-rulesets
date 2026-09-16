rule TTP_XOR_WriteProcessMemory_85ae {
  strings:
    $key_85ae = { d2 dc [2] e0 fe [2] e6 cb [2] c8 cb [2] f7 d7 }

  condition:
    any of them
}