rule TTP_XOR_WriteProcessMemory_83eb {
  strings:
    $key_83eb = { d4 99 [2] e6 bb [2] e0 8e [2] ce 8e [2] f1 92 }

  condition:
    any of them
}