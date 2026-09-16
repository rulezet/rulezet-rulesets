rule TTP_XOR_WriteProcessMemory_0d4b {
  strings:
    $key_0d4b = { 5a 39 [2] 68 1b [2] 6e 2e [2] 40 2e [2] 7f 32 }

  condition:
    any of them
}