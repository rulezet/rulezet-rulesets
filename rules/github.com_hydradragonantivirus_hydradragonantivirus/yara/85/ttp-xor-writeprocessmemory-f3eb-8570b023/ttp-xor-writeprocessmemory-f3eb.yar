rule TTP_XOR_WriteProcessMemory_f3eb {
  strings:
    $key_f3eb = { a4 99 [2] 96 bb [2] 90 8e [2] be 8e [2] 81 92 }

  condition:
    any of them
}