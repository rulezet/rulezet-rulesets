rule TTP_XOR_WriteProcessMemory_2d3b {
  strings:
    $key_2d3b = { 7a 49 [2] 48 6b [2] 4e 5e [2] 60 5e [2] 5f 42 }

  condition:
    any of them
}