rule TTP_XOR_WriteProcessMemory_157b {
  strings:
    $key_157b = { 42 09 [2] 70 2b [2] 76 1e [2] 58 1e [2] 67 02 }

  condition:
    any of them
}