rule TTP_XOR_WriteProcessMemory_933f {
  strings:
    $key_933f = { c4 4d [2] f6 6f [2] f0 5a [2] de 5a [2] e1 46 }

  condition:
    any of them
}