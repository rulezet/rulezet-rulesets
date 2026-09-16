rule TTP_XOR_WriteProcessMemory_5c4b {
  strings:
    $key_5c4b = { 0b 39 [2] 39 1b [2] 3f 2e [2] 11 2e [2] 2e 32 }

  condition:
    any of them
}