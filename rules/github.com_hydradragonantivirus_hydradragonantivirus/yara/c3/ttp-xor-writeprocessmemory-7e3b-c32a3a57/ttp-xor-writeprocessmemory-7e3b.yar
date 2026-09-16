rule TTP_XOR_WriteProcessMemory_7e3b {
  strings:
    $key_7e3b = { 29 49 [2] 1b 6b [2] 1d 5e [2] 33 5e [2] 0c 42 }

  condition:
    any of them
}