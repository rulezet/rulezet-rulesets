rule TTP_XOR_WriteProcessMemory_970f {
  strings:
    $key_970f = { c0 7d [2] f2 5f [2] f4 6a [2] da 6a [2] e5 76 }

  condition:
    any of them
}