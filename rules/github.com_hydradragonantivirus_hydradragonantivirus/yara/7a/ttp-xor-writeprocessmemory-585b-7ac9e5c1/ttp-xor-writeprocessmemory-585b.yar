rule TTP_XOR_WriteProcessMemory_585b {
  strings:
    $key_585b = { 0f 29 [2] 3d 0b [2] 3b 3e [2] 15 3e [2] 2a 22 }

  condition:
    any of them
}