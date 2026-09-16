rule TTP_XOR_WriteProcessMemory_86ff {
  strings:
    $key_86ff = { d1 8d [2] e3 af [2] e5 9a [2] cb 9a [2] f4 86 }

  condition:
    any of them
}