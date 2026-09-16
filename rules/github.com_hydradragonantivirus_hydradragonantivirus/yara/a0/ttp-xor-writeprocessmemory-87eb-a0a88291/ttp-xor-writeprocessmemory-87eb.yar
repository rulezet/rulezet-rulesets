rule TTP_XOR_WriteProcessMemory_87eb {
  strings:
    $key_87eb = { d0 99 [2] e2 bb [2] e4 8e [2] ca 8e [2] f5 92 }

  condition:
    any of them
}