rule TTP_XOR_WriteProcessMemory_227b {
  strings:
    $key_227b = { 75 09 [2] 47 2b [2] 41 1e [2] 6f 1e [2] 50 02 }

  condition:
    any of them
}