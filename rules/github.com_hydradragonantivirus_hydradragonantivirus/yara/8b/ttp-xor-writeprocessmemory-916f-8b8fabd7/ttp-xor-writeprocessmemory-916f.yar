rule TTP_XOR_WriteProcessMemory_916f {
  strings:
    $key_916f = { c6 1d [2] f4 3f [2] f2 0a [2] dc 0a [2] e3 16 }

  condition:
    any of them
}