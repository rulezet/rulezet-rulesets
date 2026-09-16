rule TTP_XOR_WriteProcessMemory_65eb {
  strings:
    $key_65eb = { 32 99 [2] 00 bb [2] 06 8e [2] 28 8e [2] 17 92 }

  condition:
    any of them
}