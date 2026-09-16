rule TTP_XOR_WriteProcessMemory_861d {
  strings:
    $key_861d = { d1 6f [2] e3 4d [2] e5 78 [2] cb 78 [2] f4 64 }

  condition:
    any of them
}