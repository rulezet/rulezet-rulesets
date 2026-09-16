rule TTP_XOR_WriteProcessMemory_861e {
  strings:
    $key_861e = { d1 6c [2] e3 4e [2] e5 7b [2] cb 7b [2] f4 67 }

  condition:
    any of them
}