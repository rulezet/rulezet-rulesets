rule TTP_XOR_WriteProcessMemory_1c7b {
  strings:
    $key_1c7b = { 4b 09 [2] 79 2b [2] 7f 1e [2] 51 1e [2] 6e 02 }

  condition:
    any of them
}