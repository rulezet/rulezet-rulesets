rule TTP_XOR_WriteProcessMemory_3c3b {
  strings:
    $key_3c3b = { 6b 49 [2] 59 6b [2] 5f 5e [2] 71 5e [2] 4e 42 }

  condition:
    any of them
}