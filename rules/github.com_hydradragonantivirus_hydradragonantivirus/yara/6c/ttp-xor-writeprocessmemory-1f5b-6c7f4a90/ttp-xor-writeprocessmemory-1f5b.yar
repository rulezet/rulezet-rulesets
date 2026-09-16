rule TTP_XOR_WriteProcessMemory_1f5b {
  strings:
    $key_1f5b = { 48 29 [2] 7a 0b [2] 7c 3e [2] 52 3e [2] 6d 22 }

  condition:
    any of them
}