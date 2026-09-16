rule TTP_XOR_WriteProcessMemory_912a {
  strings:
    $key_912a = { c6 58 [2] f4 7a [2] f2 4f [2] dc 4f [2] e3 53 }

  condition:
    any of them
}