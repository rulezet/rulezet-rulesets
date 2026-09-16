rule TTP_XOR_WriteProcessMemory_bebc {
  strings:
    $key_bebc = { e9 ce [2] db ec [2] dd d9 [2] f3 d9 [2] cc c5 }

  condition:
    any of them
}