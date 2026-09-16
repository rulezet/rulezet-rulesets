rule TTP_XOR_WriteProcessMemory_5a5b {
  strings:
    $key_5a5b = { 0d 29 [2] 3f 0b [2] 39 3e [2] 17 3e [2] 28 22 }

  condition:
    any of them
}