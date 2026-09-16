rule TTP_XOR_WriteProcessMemory_774b {
  strings:
    $key_774b = { 20 39 [2] 12 1b [2] 14 2e [2] 3a 2e [2] 05 32 }

  condition:
    any of them
}