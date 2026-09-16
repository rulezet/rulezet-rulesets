rule TTP_XOR_WriteProcessMemory_584b {
  strings:
    $key_584b = { 0f 39 [2] 3d 1b [2] 3b 2e [2] 15 2e [2] 2a 32 }

  condition:
    any of them
}