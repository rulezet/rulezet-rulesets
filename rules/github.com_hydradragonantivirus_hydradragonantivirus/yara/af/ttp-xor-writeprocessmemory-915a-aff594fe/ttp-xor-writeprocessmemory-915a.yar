rule TTP_XOR_WriteProcessMemory_915a {
  strings:
    $key_915a = { c6 28 [2] f4 0a [2] f2 3f [2] dc 3f [2] e3 23 }

  condition:
    any of them
}