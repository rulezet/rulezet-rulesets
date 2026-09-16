rule TTP_XOR_WriteProcessMemory_225b {
  strings:
    $key_225b = { 75 29 [2] 47 0b [2] 41 3e [2] 6f 3e [2] 50 22 }

  condition:
    any of them
}