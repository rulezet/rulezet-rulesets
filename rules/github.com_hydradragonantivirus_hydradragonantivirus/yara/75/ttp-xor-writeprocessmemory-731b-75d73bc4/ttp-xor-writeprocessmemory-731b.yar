rule TTP_XOR_WriteProcessMemory_731b {
  strings:
    $key_731b = { 24 69 [2] 16 4b [2] 10 7e [2] 3e 7e [2] 01 62 }

  condition:
    any of them
}