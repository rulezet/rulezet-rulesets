rule TTP_XOR_WriteProcessMemory_94ea {
  strings:
    $key_94ea = { c3 98 [2] f1 ba [2] f7 8f [2] d9 8f [2] e6 93 }

  condition:
    any of them
}