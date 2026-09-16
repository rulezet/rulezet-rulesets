rule TTP_XOR_WriteProcessMemory_94ff {
  strings:
    $key_94ff = { c3 8d [2] f1 af [2] f7 9a [2] d9 9a [2] e6 86 }

  condition:
    any of them
}