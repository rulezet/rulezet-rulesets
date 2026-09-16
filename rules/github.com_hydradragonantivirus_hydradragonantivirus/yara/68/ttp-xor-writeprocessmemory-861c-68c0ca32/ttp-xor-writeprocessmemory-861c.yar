rule TTP_XOR_WriteProcessMemory_861c {
  strings:
    $key_861c = { d1 6e [2] e3 4c [2] e5 79 [2] cb 79 [2] f4 65 }

  condition:
    any of them
}