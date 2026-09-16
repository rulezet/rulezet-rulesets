rule TTP_XOR_WriteProcessMemory_194b {
  strings:
    $key_194b = { 4e 39 [2] 7c 1b [2] 7a 2e [2] 54 2e [2] 6b 32 }

  condition:
    any of them
}