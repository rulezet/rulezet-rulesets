rule TTP_XOR_WriteProcessMemory_70eb {
  strings:
    $key_70eb = { 27 99 [2] 15 bb [2] 13 8e [2] 3d 8e [2] 02 92 }

  condition:
    any of them
}