rule TTP_XOR_WriteProcessMemory_8aea {
  strings:
    $key_8aea = { dd 98 [2] ef ba [2] e9 8f [2] c7 8f [2] f8 93 }

  condition:
    any of them
}