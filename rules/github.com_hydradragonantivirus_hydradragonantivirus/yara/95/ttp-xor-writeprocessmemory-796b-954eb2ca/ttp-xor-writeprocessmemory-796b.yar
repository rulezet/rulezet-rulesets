rule TTP_XOR_WriteProcessMemory_796b {
  strings:
    $key_796b = { 2e 19 [2] 1c 3b [2] 1a 0e [2] 34 0e [2] 0b 12 }

  condition:
    any of them
}