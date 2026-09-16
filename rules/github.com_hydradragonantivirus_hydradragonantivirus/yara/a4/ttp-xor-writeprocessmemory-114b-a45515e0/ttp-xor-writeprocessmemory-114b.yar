rule TTP_XOR_WriteProcessMemory_114b {
  strings:
    $key_114b = { 46 39 [2] 74 1b [2] 72 2e [2] 5c 2e [2] 63 32 }

  condition:
    any of them
}