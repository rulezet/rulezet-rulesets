rule TTP_XOR_WriteProcessMemory_793b {
  strings:
    $key_793b = { 2e 49 [2] 1c 6b [2] 1a 5e [2] 34 5e [2] 0b 42 }

  condition:
    any of them
}