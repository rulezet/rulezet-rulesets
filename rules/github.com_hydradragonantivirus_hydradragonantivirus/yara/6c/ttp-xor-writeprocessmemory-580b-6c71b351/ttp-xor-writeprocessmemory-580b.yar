rule TTP_XOR_WriteProcessMemory_580b {
  strings:
    $key_580b = { 0f 79 [2] 3d 5b [2] 3b 6e [2] 15 6e [2] 2a 72 }

  condition:
    any of them
}