rule TTP_XOR_WriteProcessMemory_85ea {
  strings:
    $key_85ea = { d2 98 [2] e0 ba [2] e6 8f [2] c8 8f [2] f7 93 }

  condition:
    any of them
}