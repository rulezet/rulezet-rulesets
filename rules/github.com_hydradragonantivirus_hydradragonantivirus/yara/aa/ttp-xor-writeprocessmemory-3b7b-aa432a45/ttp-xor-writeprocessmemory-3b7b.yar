rule TTP_XOR_WriteProcessMemory_3b7b {
  strings:
    $key_3b7b = { 6c 09 [2] 5e 2b [2] 58 1e [2] 76 1e [2] 49 02 }

  condition:
    any of them
}