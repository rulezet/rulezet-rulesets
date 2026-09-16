rule TTP_XOR_WriteProcessMemory_913d {
  strings:
    $key_913d = { c6 4f [2] f4 6d [2] f2 58 [2] dc 58 [2] e3 44 }

  condition:
    any of them
}