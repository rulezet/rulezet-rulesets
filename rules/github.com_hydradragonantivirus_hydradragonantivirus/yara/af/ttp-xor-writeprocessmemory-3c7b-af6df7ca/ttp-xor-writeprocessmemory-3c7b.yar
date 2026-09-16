rule TTP_XOR_WriteProcessMemory_3c7b {
  strings:
    $key_3c7b = { 6b 09 [2] 59 2b [2] 5f 1e [2] 71 1e [2] 4e 02 }

  condition:
    any of them
}