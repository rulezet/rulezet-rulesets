rule TTP_XOR_WriteProcessMemory_952d {
  strings:
    $key_952d = { c2 5f [2] f0 7d [2] f6 48 [2] d8 48 [2] e7 54 }

  condition:
    any of them
}