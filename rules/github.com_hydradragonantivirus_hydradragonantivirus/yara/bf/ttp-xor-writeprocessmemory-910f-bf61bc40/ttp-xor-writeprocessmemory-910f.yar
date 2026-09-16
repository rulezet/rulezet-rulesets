rule TTP_XOR_WriteProcessMemory_910f {
  strings:
    $key_910f = { c6 7d [2] f4 5f [2] f2 6a [2] dc 6a [2] e3 76 }

  condition:
    any of them
}