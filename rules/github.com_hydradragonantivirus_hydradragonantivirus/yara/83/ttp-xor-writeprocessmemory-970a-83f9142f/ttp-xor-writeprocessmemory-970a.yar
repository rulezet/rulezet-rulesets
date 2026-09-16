rule TTP_XOR_WriteProcessMemory_970a {
  strings:
    $key_970a = { c0 78 [2] f2 5a [2] f4 6f [2] da 6f [2] e5 73 }

  condition:
    any of them
}