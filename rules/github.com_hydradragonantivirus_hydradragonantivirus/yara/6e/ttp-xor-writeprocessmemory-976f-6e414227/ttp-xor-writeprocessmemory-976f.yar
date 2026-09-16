rule TTP_XOR_WriteProcessMemory_976f {
  strings:
    $key_976f = { c0 1d [2] f2 3f [2] f4 0a [2] da 0a [2] e5 16 }

  condition:
    any of them
}