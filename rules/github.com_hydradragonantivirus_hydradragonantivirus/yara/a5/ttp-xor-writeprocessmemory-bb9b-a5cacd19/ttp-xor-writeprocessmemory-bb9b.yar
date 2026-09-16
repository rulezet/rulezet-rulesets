rule TTP_XOR_WriteProcessMemory_bb9b {
  strings:
    $key_bb9b = { ec e9 [2] de cb [2] d8 fe [2] f6 fe [2] c9 e2 }

  condition:
    any of them
}