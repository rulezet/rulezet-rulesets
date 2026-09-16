rule TTP_XOR_WriteProcessMemory_abbc {
  strings:
    $key_abbc = { fc ce [2] ce ec [2] c8 d9 [2] e6 d9 [2] d9 c5 }

  condition:
    any of them
}