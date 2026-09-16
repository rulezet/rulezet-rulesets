rule TTP_XOR_WriteProcessMemory_8aca {
  strings:
    $key_8aca = { dd b8 [2] ef 9a [2] e9 af [2] c7 af [2] f8 b3 }

  condition:
    any of them
}