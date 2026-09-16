rule TTP_XOR_WriteProcessMemory_6b6b {
  strings:
    $key_6b6b = { 3c 19 [2] 0e 3b [2] 08 0e [2] 26 0e [2] 19 12 }

  condition:
    any of them
}