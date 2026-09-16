rule TTP_XOR_WriteProcessMemory_beac {
  strings:
    $key_beac = { e9 de [2] db fc [2] dd c9 [2] f3 c9 [2] cc d5 }

  condition:
    any of them
}