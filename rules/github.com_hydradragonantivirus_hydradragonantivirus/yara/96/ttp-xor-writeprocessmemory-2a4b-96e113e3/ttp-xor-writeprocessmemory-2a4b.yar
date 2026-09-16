rule TTP_XOR_WriteProcessMemory_2a4b {
  strings:
    $key_2a4b = { 7d 39 [2] 4f 1b [2] 49 2e [2] 67 2e [2] 58 32 }

  condition:
    any of them
}