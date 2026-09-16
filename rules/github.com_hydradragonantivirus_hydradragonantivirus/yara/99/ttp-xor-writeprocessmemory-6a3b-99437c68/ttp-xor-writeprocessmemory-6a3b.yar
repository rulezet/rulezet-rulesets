rule TTP_XOR_WriteProcessMemory_6a3b {
  strings:
    $key_6a3b = { 3d 49 [2] 0f 6b [2] 09 5e [2] 27 5e [2] 18 42 }

  condition:
    any of them
}