rule TTP_XOR_WriteProcessMemory_8a3a {
  strings:
    $key_8a3a = { dd 48 [2] ef 6a [2] e9 5f [2] c7 5f [2] f8 43 }

  condition:
    any of them
}