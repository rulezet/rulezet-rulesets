rule TTP_XOR_WriteProcessMemory_8a0a {
  strings:
    $key_8a0a = { dd 78 [2] ef 5a [2] e9 6f [2] c7 6f [2] f8 73 }

  condition:
    any of them
}