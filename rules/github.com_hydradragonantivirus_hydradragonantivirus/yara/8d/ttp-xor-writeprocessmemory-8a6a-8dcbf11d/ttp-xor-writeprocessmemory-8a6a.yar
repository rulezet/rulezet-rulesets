rule TTP_XOR_WriteProcessMemory_8a6a {
  strings:
    $key_8a6a = { dd 18 [2] ef 3a [2] e9 0f [2] c7 0f [2] f8 13 }

  condition:
    any of them
}