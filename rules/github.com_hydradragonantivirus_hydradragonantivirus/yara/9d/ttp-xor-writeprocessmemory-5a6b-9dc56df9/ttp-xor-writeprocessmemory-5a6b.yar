rule TTP_XOR_WriteProcessMemory_5a6b {
  strings:
    $key_5a6b = { 0d 19 [2] 3f 3b [2] 39 0e [2] 17 0e [2] 28 12 }

  condition:
    any of them
}