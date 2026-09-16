rule TTP_XOR_WriteProcessMemory_7b3b {
  strings:
    $key_7b3b = { 2c 49 [2] 1e 6b [2] 18 5e [2] 36 5e [2] 09 42 }

  condition:
    any of them
}