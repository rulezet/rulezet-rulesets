rule TTP_XOR_WriteProcessMemory_865a {
  strings:
    $key_865a = { d1 28 [2] e3 0a [2] e5 3f [2] cb 3f [2] f4 23 }

  condition:
    any of them
}