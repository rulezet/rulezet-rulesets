rule TTP_XOR_WriteProcessMemory_930a {
  strings:
    $key_930a = { c4 78 [2] f6 5a [2] f0 6f [2] de 6f [2] e1 73 }

  condition:
    any of them
}