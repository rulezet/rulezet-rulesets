rule TTP_XOR_WriteProcessMemory_584e {
  strings:
    $key_584e = { 0f 3c [2] 3d 1e [2] 3b 2b [2] 15 2b [2] 2a 37 }

  condition:
    any of them
}