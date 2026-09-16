rule TTP_XOR_WriteProcessMemory_184b {
  strings:
    $key_184b = { 4f 39 [2] 7d 1b [2] 7b 2e [2] 55 2e [2] 6a 32 }

  condition:
    any of them
}