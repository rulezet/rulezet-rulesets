rule TTP_XOR_WriteProcessMemory_bee9 {
  strings:
    $key_bee9 = { e9 9b [2] db b9 [2] dd 8c [2] f3 8c [2] cc 90 }

  condition:
    any of them
}