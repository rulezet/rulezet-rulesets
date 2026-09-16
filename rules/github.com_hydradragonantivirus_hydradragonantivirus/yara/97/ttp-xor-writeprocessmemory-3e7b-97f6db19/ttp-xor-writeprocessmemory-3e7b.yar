rule TTP_XOR_WriteProcessMemory_3e7b {
  strings:
    $key_3e7b = { 69 09 [2] 5b 2b [2] 5d 1e [2] 73 1e [2] 4c 02 }

  condition:
    any of them
}