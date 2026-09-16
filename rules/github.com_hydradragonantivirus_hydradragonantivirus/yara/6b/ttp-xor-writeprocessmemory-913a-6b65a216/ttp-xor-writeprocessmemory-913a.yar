rule TTP_XOR_WriteProcessMemory_913a {
  strings:
    $key_913a = { c6 48 [2] f4 6a [2] f2 5f [2] dc 5f [2] e3 43 }

  condition:
    any of them
}