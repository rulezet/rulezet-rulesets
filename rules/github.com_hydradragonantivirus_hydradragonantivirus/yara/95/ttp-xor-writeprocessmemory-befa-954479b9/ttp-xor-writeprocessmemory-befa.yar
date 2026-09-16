rule TTP_XOR_WriteProcessMemory_befa {
  strings:
    $key_befa = { e9 88 [2] db aa [2] dd 9f [2] f3 9f [2] cc 83 }

  condition:
    any of them
}