rule TTP_XOR_WriteProcessMemory_3e4b {
  strings:
    $key_3e4b = { 69 39 [2] 5b 1b [2] 5d 2e [2] 73 2e [2] 4c 32 }

  condition:
    any of them
}