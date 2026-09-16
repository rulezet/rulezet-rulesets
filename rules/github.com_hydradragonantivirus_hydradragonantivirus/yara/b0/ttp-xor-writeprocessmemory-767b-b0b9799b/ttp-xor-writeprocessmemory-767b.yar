rule TTP_XOR_WriteProcessMemory_767b {
  strings:
    $key_767b = { 21 09 [2] 13 2b [2] 15 1e [2] 3b 1e [2] 04 02 }

  condition:
    any of them
}