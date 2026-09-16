rule TTP_XOR_WriteProcessMemory_4d7b {
  strings:
    $key_4d7b = { 1a 09 [2] 28 2b [2] 2e 1e [2] 00 1e [2] 3f 02 }

  condition:
    any of them
}