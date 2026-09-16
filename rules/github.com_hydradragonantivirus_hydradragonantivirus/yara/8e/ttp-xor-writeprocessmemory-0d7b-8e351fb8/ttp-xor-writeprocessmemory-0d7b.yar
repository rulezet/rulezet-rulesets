rule TTP_XOR_WriteProcessMemory_0d7b {
  strings:
    $key_0d7b = { 5a 09 [2] 68 2b [2] 6e 1e [2] 40 1e [2] 7f 02 }

  condition:
    any of them
}