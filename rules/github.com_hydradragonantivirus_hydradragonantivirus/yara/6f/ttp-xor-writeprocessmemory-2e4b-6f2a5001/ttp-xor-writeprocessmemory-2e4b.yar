rule TTP_XOR_WriteProcessMemory_2e4b {
  strings:
    $key_2e4b = { 79 39 [2] 4b 1b [2] 4d 2e [2] 63 2e [2] 5c 32 }

  condition:
    any of them
}