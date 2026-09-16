rule TTP_XOR_WriteProcessMemory_3d4b {
  strings:
    $key_3d4b = { 6a 39 [2] 58 1b [2] 5e 2e [2] 70 2e [2] 4f 32 }

  condition:
    any of them
}