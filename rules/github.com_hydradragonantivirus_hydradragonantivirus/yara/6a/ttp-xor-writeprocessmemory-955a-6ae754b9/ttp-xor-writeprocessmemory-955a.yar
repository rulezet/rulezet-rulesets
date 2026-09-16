rule TTP_XOR_WriteProcessMemory_955a {
  strings:
    $key_955a = { c2 28 [2] f0 0a [2] f6 3f [2] d8 3f [2] e7 23 }

  condition:
    any of them
}