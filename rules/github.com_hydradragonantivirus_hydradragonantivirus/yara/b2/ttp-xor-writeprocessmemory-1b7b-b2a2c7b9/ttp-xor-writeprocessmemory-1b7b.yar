rule TTP_XOR_WriteProcessMemory_1b7b {
  strings:
    $key_1b7b = { 4c 09 [2] 7e 2b [2] 78 1e [2] 56 1e [2] 69 02 }

  condition:
    any of them
}