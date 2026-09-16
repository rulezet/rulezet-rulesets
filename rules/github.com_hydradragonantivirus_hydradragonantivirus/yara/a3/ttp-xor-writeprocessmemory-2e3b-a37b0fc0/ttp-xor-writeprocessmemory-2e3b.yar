rule TTP_XOR_WriteProcessMemory_2e3b {
  strings:
    $key_2e3b = { 79 49 [2] 4b 6b [2] 4d 5e [2] 63 5e [2] 5c 42 }

  condition:
    any of them
}