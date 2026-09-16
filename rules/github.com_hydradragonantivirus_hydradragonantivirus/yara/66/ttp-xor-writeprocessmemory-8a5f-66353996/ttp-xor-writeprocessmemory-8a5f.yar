rule TTP_XOR_WriteProcessMemory_8a5f {
  strings:
    $key_8a5f = { dd 2d [2] ef 0f [2] e9 3a [2] c7 3a [2] f8 26 }

  condition:
    any of them
}