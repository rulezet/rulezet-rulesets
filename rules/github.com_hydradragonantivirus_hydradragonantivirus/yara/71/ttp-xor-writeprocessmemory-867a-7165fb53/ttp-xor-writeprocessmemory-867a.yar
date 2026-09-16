rule TTP_XOR_WriteProcessMemory_867a {
  strings:
    $key_867a = { d1 08 [2] e3 2a [2] e5 1f [2] cb 1f [2] f4 03 }

  condition:
    any of them
}