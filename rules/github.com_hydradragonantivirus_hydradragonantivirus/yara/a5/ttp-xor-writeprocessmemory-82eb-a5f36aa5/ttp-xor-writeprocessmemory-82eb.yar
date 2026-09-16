rule TTP_XOR_WriteProcessMemory_82eb {
  strings:
    $key_82eb = { d5 99 [2] e7 bb [2] e1 8e [2] cf 8e [2] f0 92 }

  condition:
    any of them
}