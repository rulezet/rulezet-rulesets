rule TTP_XOR_WriteProcessMemory_1d3b {
  strings:
    $key_1d3b = { 4a 49 [2] 78 6b [2] 7e 5e [2] 50 5e [2] 6f 42 }

  condition:
    any of them
}