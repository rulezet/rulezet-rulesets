rule TTP_XOR_WriteProcessMemory_97ca {
  strings:
    $key_97ca = { c0 b8 [2] f2 9a [2] f4 af [2] da af [2] e5 b3 }

  condition:
    any of them
}