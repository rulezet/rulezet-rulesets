rule TTP_XOR_WriteProcessMemory_693b {
  strings:
    $key_693b = { 3e 49 [2] 0c 6b [2] 0a 5e [2] 24 5e [2] 1b 42 }

  condition:
    any of them
}