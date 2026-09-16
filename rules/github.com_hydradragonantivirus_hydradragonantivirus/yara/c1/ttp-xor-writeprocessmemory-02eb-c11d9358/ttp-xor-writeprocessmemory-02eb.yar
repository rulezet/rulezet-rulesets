rule TTP_XOR_WriteProcessMemory_02eb {
  strings:
    $key_02eb = { 55 99 [2] 67 bb [2] 61 8e [2] 4f 8e [2] 70 92 }

  condition:
    any of them
}