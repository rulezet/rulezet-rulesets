rule TTP_XOR_WriteProcessMemory_95ea {
  strings:
    $key_95ea = { c2 98 [2] f0 ba [2] f6 8f [2] d8 8f [2] e7 93 }

  condition:
    any of them
}