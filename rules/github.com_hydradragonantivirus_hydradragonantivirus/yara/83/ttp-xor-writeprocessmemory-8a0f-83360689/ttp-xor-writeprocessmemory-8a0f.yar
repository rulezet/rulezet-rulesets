rule TTP_XOR_WriteProcessMemory_8a0f {
  strings:
    $key_8a0f = { dd 7d [2] ef 5f [2] e9 6a [2] c7 6a [2] f8 76 }

  condition:
    any of them
}