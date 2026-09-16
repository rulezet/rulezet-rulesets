rule TTP_XOR_WriteProcessMemory_903d {
  strings:
    $key_903d = { c7 4f [2] f5 6d [2] f3 58 [2] dd 58 [2] e2 44 }

  condition:
    any of them
}