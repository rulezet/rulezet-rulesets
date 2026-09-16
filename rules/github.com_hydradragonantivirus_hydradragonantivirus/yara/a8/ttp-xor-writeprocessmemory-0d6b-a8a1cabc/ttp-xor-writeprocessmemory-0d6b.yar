rule TTP_XOR_WriteProcessMemory_0d6b {
  strings:
    $key_0d6b = { 5a 19 [2] 68 3b [2] 6e 0e [2] 40 0e [2] 7f 12 }

  condition:
    any of them
}