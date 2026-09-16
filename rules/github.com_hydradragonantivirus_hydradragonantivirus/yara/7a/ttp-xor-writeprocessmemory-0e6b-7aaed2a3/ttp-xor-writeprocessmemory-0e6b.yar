rule TTP_XOR_WriteProcessMemory_0e6b {
  strings:
    $key_0e6b = { 59 19 [2] 6b 3b [2] 6d 0e [2] 43 0e [2] 7c 12 }

  condition:
    any of them
}