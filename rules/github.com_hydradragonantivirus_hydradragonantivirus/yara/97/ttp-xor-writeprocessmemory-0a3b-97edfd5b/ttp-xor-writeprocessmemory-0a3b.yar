rule TTP_XOR_WriteProcessMemory_0a3b {
  strings:
    $key_0a3b = { 5d 49 [2] 6f 6b [2] 69 5e [2] 47 5e [2] 78 42 }

  condition:
    any of them
}