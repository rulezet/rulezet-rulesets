rule TTP_XOR_WriteProcessMemory_b44a {
  strings:
    $key_b44a = { e3 38 [2] d1 1a [2] d7 2f [2] f9 2f [2] c6 33 }

  condition:
    any of them
}