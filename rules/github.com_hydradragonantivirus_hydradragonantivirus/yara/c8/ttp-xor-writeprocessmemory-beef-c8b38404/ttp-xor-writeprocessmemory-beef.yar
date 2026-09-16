rule TTP_XOR_WriteProcessMemory_beef {
  strings:
    $key_beef = { e9 9d [2] db bf [2] dd 8a [2] f3 8a [2] cc 96 }

  condition:
    any of them
}