rule TTP_XOR_WriteProcessMemory_3b6b {
  strings:
    $key_3b6b = { 6c 19 [2] 5e 3b [2] 58 0e [2] 76 0e [2] 49 12 }

  condition:
    any of them
}