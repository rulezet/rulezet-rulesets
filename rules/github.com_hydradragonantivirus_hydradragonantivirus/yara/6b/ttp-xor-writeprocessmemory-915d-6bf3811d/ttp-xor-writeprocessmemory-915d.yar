rule TTP_XOR_WriteProcessMemory_915d {
  strings:
    $key_915d = { c6 2f [2] f4 0d [2] f2 38 [2] dc 38 [2] e3 24 }

  condition:
    any of them
}