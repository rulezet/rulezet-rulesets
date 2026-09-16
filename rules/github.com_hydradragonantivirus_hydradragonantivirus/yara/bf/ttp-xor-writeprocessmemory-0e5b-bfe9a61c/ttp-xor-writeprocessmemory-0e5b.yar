rule TTP_XOR_WriteProcessMemory_0e5b {
  strings:
    $key_0e5b = { 59 29 [2] 6b 0b [2] 6d 3e [2] 43 3e [2] 7c 22 }

  condition:
    any of them
}