rule TTP_XOR_WriteProcessMemory_34eb {
  strings:
    $key_34eb = { 63 99 [2] 51 bb [2] 57 8e [2] 79 8e [2] 46 92 }

  condition:
    any of them
}