rule TTP_XOR_WriteProcessMemory_7c3b {
  strings:
    $key_7c3b = { 2b 49 [2] 19 6b [2] 1f 5e [2] 31 5e [2] 0e 42 }

  condition:
    any of them
}