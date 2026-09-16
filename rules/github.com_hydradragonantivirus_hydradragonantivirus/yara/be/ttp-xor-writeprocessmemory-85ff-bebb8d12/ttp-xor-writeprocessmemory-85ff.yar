rule TTP_XOR_WriteProcessMemory_85ff {
  strings:
    $key_85ff = { d2 8d [2] e0 af [2] e6 9a [2] c8 9a [2] f7 86 }

  condition:
    any of them
}