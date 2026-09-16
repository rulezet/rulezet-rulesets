rule TTP_XOR_WriteProcessMemory_fa7b {
  strings:
    $key_fa7b = { ad 09 [2] 9f 2b [2] 99 1e [2] b7 1e [2] 88 02 }

  condition:
    any of them
}