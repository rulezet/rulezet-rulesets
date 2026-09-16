rule TTP_XOR_WriteProcessMemory_920f {
  strings:
    $key_920f = { c5 7d [2] f7 5f [2] f1 6a [2] df 6a [2] e0 76 }

  condition:
    any of them
}