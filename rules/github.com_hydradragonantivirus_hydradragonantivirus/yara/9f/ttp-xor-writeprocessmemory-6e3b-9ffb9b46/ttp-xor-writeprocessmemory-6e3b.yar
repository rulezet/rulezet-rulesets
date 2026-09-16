rule TTP_XOR_WriteProcessMemory_6e3b {
  strings:
    $key_6e3b = { 39 49 [2] 0b 6b [2] 0d 5e [2] 23 5e [2] 1c 42 }

  condition:
    any of them
}