rule TTP_XOR_WriteProcessMemory_7a3b {
  strings:
    $key_7a3b = { 2d 49 [2] 1f 6b [2] 19 5e [2] 37 5e [2] 08 42 }

  condition:
    any of them
}