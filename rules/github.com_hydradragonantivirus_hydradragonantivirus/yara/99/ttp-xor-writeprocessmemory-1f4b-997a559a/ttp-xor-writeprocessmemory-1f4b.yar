rule TTP_XOR_WriteProcessMemory_1f4b {
  strings:
    $key_1f4b = { 48 39 [2] 7a 1b [2] 7c 2e [2] 52 2e [2] 6d 32 }

  condition:
    any of them
}