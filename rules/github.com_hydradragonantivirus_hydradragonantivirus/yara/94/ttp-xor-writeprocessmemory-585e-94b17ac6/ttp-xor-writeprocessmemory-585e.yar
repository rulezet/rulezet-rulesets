rule TTP_XOR_WriteProcessMemory_585e {
  strings:
    $key_585e = { 0f 2c [2] 3d 0e [2] 3b 3b [2] 15 3b [2] 2a 27 }

  condition:
    any of them
}