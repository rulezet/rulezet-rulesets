rule TTP_XOR_WriteProcessMemory_867f {
  strings:
    $key_867f = { d1 0d [2] e3 2f [2] e5 1a [2] cb 1a [2] f4 06 }

  condition:
    any of them
}