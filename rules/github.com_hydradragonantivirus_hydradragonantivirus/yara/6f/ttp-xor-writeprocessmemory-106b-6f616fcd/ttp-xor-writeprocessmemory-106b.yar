rule TTP_XOR_WriteProcessMemory_106b {
  strings:
    $key_106b = { 47 19 [2] 75 3b [2] 73 0e [2] 5d 0e [2] 62 12 }

  condition:
    any of them
}