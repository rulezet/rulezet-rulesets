rule TTP_XOR_WriteProcessMemory_957d {
  strings:
    $key_957d = { c2 0f [2] f0 2d [2] f6 18 [2] d8 18 [2] e7 04 }

  condition:
    any of them
}