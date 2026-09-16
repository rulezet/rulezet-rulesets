rule TTP_XOR_WriteProcessMemory_7c4b {
  strings:
    $key_7c4b = { 2b 39 [2] 19 1b [2] 1f 2e [2] 31 2e [2] 0e 32 }

  condition:
    any of them
}