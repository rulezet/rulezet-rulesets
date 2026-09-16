rule TTP_XOR_WriteProcessMemory_3d5b {
  strings:
    $key_3d5b = { 6a 29 [2] 58 0b [2] 5e 3e [2] 70 3e [2] 4f 22 }

  condition:
    any of them
}