rule TTP_XOR_WriteProcessMemory_0c6b {
  strings:
    $key_0c6b = { 5b 19 [2] 69 3b [2] 6f 0e [2] 41 0e [2] 7e 12 }

  condition:
    any of them
}