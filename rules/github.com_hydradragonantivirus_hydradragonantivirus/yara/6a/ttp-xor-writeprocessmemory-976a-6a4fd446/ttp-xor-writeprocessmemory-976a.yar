rule TTP_XOR_WriteProcessMemory_976a {
  strings:
    $key_976a = { c0 18 [2] f2 3a [2] f4 0f [2] da 0f [2] e5 13 }

  condition:
    any of them
}