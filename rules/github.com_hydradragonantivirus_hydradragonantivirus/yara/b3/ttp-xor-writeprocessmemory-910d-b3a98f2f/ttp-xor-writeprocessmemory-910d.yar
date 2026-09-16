rule TTP_XOR_WriteProcessMemory_910d {
  strings:
    $key_910d = { c6 7f [2] f4 5d [2] f2 68 [2] dc 68 [2] e3 74 }

  condition:
    any of them
}