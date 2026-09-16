rule TTP_XOR_WriteProcessMemory_1f3b {
  strings:
    $key_1f3b = { 48 49 [2] 7a 6b [2] 7c 5e [2] 52 5e [2] 6d 42 }

  condition:
    any of them
}