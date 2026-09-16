rule TTP_XOR_WriteProcessMemory_2e6b {
  strings:
    $key_2e6b = { 79 19 [2] 4b 3b [2] 4d 0e [2] 63 0e [2] 5c 12 }

  condition:
    any of them
}