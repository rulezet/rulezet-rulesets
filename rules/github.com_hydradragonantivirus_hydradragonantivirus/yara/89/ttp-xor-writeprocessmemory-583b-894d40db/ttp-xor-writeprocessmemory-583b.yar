rule TTP_XOR_WriteProcessMemory_583b {
  strings:
    $key_583b = { 0f 49 [2] 3d 6b [2] 3b 5e [2] 15 5e [2] 2a 42 }

  condition:
    any of them
}