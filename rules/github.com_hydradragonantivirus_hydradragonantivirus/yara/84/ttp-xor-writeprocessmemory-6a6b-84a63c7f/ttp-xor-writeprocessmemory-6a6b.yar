rule TTP_XOR_WriteProcessMemory_6a6b {
  strings:
    $key_6a6b = { 3d 19 [2] 0f 3b [2] 09 0e [2] 27 0e [2] 18 12 }

  condition:
    any of them
}