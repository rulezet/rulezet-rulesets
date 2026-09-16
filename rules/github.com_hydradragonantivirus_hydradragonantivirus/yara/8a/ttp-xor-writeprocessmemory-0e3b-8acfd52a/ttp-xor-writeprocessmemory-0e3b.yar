rule TTP_XOR_WriteProcessMemory_0e3b {
  strings:
    $key_0e3b = { 59 49 [2] 6b 6b [2] 6d 5e [2] 43 5e [2] 7c 42 }

  condition:
    any of them
}