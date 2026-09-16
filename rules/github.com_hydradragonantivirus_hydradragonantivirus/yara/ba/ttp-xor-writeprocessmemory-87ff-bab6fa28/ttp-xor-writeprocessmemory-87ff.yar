rule TTP_XOR_WriteProcessMemory_87ff {
  strings:
    $key_87ff = { d0 8d [2] e2 af [2] e4 9a [2] ca 9a [2] f5 86 }

  condition:
    any of them
}