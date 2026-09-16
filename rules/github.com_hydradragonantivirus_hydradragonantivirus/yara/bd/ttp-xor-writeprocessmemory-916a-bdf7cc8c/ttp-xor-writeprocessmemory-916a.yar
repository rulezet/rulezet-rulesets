rule TTP_XOR_WriteProcessMemory_916a {
  strings:
    $key_916a = { c6 18 [2] f4 3a [2] f2 0f [2] dc 0f [2] e3 13 }

  condition:
    any of them
}