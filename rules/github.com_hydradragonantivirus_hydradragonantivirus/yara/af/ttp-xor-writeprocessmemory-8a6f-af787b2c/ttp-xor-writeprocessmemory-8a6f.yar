rule TTP_XOR_WriteProcessMemory_8a6f {
  strings:
    $key_8a6f = { dd 1d [2] ef 3f [2] e9 0a [2] c7 0a [2] f8 16 }

  condition:
    any of them
}