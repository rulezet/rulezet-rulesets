rule TTP_XOR_WriteProcessMemory_933d {
  strings:
    $key_933d = { c4 4f [2] f6 6d [2] f0 58 [2] de 58 [2] e1 44 }

  condition:
    any of them
}