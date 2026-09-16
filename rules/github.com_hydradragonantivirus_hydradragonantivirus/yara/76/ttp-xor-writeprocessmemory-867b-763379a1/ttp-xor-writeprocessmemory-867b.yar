rule TTP_XOR_WriteProcessMemory_867b {
  strings:
    $key_867b = { d1 09 [2] e3 2b [2] e5 1e [2] cb 1e [2] f4 02 }

  condition:
    any of them
}