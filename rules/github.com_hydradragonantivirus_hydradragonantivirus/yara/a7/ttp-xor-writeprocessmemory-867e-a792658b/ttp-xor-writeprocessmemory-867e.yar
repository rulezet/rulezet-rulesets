rule TTP_XOR_WriteProcessMemory_867e {
  strings:
    $key_867e = { d1 0c [2] e3 2e [2] e5 1b [2] cb 1b [2] f4 07 }

  condition:
    any of them
}