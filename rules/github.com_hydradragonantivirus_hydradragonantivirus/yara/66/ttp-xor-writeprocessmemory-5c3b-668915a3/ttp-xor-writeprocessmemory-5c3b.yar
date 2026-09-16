rule TTP_XOR_WriteProcessMemory_5c3b {
  strings:
    $key_5c3b = { 0b 49 [2] 39 6b [2] 3f 5e [2] 11 5e [2] 2e 42 }

  condition:
    any of them
}