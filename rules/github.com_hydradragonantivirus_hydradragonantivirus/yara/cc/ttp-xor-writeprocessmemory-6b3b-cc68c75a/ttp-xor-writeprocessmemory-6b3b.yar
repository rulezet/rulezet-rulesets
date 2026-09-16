rule TTP_XOR_WriteProcessMemory_6b3b {
  strings:
    $key_6b3b = { 3c 49 [2] 0e 6b [2] 08 5e [2] 26 5e [2] 19 42 }

  condition:
    any of them
}