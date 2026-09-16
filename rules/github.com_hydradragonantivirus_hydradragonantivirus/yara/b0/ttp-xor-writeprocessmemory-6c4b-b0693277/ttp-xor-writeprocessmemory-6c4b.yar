rule TTP_XOR_WriteProcessMemory_6c4b {
  strings:
    $key_6c4b = { 3b 39 [2] 09 1b [2] 0f 2e [2] 21 2e [2] 1e 32 }

  condition:
    any of them
}