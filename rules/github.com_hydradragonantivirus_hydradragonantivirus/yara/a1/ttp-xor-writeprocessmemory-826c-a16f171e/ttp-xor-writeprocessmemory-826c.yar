rule TTP_XOR_WriteProcessMemory_826c {
  strings:
    $key_826c = { d5 1e [2] e7 3c [2] e1 09 [2] cf 09 [2] f0 15 }

  condition:
    any of them
}