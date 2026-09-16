rule TTP_XOR_WriteProcessMemory_80ae {
  strings:
    $key_80ae = { d7 dc [2] e5 fe [2] e3 cb [2] cd cb [2] f2 d7 }

  condition:
    any of them
}