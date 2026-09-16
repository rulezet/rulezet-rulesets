rule TTP_XOR_WriteProcessMemory_6e5b {
  strings:
    $key_6e5b = { 39 29 [2] 0b 0b [2] 0d 3e [2] 23 3e [2] 1c 22 }

  condition:
    any of them
}