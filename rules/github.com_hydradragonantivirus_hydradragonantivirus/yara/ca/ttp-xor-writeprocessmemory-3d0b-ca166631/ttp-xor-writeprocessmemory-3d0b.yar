rule TTP_XOR_WriteProcessMemory_3d0b {
  strings:
    $key_3d0b = { 6a 79 [2] 58 5b [2] 5e 6e [2] 70 6e [2] 4f 72 }

  condition:
    any of them
}