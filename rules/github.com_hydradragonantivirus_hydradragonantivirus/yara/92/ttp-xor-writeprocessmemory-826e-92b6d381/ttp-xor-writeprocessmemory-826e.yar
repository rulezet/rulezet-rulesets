rule TTP_XOR_WriteProcessMemory_826e {
  strings:
    $key_826e = { d5 1c [2] e7 3e [2] e1 0b [2] cf 0b [2] f0 17 }

  condition:
    any of them
}