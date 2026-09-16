rule TTP_XOR_WriteProcessMemory_efbe {
  strings:
    $key_efbe = { b8 cc [2] 8a ee [2] 8c db [2] a2 db [2] 9d c7 }

  condition:
    any of them
}