rule TTP_XOR_WriteProcessMemory_8aac {
  strings:
    $key_8aac = { dd de [2] ef fc [2] e9 c9 [2] c7 c9 [2] f8 d5 }

  condition:
    any of them
}