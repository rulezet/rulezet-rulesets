rule TTP_XOR_WriteProcessMemory_6c7b {
  strings:
    $key_6c7b = { 3b 09 [2] 09 2b [2] 0f 1e [2] 21 1e [2] 1e 02 }

  condition:
    any of them
}