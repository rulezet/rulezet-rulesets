rule TTP_XOR_WriteProcessMemory_05eb {
  strings:
    $key_05eb = { 52 99 [2] 60 bb [2] 66 8e [2] 48 8e [2] 77 92 }

  condition:
    any of them
}