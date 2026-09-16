rule TTP_XOR_WriteProcessMemory_220b {
  strings:
    $key_220b = { 75 79 [2] 47 5b [2] 41 6e [2] 6f 6e [2] 50 72 }

  condition:
    any of them
}