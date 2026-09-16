rule TTP_XOR_WriteProcessMemory_4b6b {
  strings:
    $key_4b6b = { 1c 19 [2] 2e 3b [2] 28 0e [2] 06 0e [2] 39 12 }

  condition:
    any of them
}