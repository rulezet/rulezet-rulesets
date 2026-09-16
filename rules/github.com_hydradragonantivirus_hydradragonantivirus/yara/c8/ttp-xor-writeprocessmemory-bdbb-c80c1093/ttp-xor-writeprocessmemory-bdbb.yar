rule TTP_XOR_WriteProcessMemory_bdbb {
  strings:
    $key_bdbb = { ea c9 [2] d8 eb [2] de de [2] f0 de [2] cf c2 }

  condition:
    any of them
}