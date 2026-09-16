rule TTP_XOR_WriteProcessMemory_953a {
  strings:
    $key_953a = { c2 48 [2] f0 6a [2] f6 5f [2] d8 5f [2] e7 43 }

  condition:
    any of them
}