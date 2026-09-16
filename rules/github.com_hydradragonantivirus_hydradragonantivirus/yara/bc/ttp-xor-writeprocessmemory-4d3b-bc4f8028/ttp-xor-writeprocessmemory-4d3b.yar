rule TTP_XOR_WriteProcessMemory_4d3b {
  strings:
    $key_4d3b = { 1a 49 [2] 28 6b [2] 2e 5e [2] 00 5e [2] 3f 42 }

  condition:
    any of them
}