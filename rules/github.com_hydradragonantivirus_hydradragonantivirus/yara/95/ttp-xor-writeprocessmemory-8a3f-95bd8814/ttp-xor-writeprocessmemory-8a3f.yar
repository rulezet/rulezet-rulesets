rule TTP_XOR_WriteProcessMemory_8a3f {
  strings:
    $key_8a3f = { dd 4d [2] ef 6f [2] e9 5a [2] c7 5a [2] f8 46 }

  condition:
    any of them
}