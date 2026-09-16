rule TTP_XOR_WriteProcessMemory_c9eb {
  strings:
    $key_c9eb = { 9e 99 [2] ac bb [2] aa 8e [2] 84 8e [2] bb 92 }

  condition:
    any of them
}