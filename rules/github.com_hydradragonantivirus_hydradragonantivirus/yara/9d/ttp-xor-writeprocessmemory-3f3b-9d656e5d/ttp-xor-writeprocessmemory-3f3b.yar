rule TTP_XOR_WriteProcessMemory_3f3b {
  strings:
    $key_3f3b = { 68 49 [2] 5a 6b [2] 5c 5e [2] 72 5e [2] 4d 42 }

  condition:
    any of them
}