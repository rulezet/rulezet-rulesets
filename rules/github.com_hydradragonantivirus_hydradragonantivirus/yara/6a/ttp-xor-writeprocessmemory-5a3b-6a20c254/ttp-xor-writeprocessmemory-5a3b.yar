rule TTP_XOR_WriteProcessMemory_5a3b {
  strings:
    $key_5a3b = { 0d 49 [2] 3f 6b [2] 39 5e [2] 17 5e [2] 28 42 }

  condition:
    any of them
}