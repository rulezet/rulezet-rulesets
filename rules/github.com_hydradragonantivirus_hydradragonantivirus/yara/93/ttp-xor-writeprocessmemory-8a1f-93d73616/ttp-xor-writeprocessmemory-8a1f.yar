rule TTP_XOR_WriteProcessMemory_8a1f {
  strings:
    $key_8a1f = { dd 6d [2] ef 4f [2] e9 7a [2] c7 7a [2] f8 66 }

  condition:
    any of them
}