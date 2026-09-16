rule TTP_XOR_WriteProcessMemory_5a4b {
  strings:
    $key_5a4b = { 0d 39 [2] 3f 1b [2] 39 2e [2] 17 2e [2] 28 32 }

  condition:
    any of them
}