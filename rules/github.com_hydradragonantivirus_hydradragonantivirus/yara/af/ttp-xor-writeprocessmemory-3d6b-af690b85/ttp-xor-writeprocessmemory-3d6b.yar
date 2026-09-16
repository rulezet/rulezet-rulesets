rule TTP_XOR_WriteProcessMemory_3d6b {
  strings:
    $key_3d6b = { 6a 19 [2] 58 3b [2] 5e 0e [2] 70 0e [2] 4f 12 }

  condition:
    any of them
}