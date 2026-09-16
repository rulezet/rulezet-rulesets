rule TTP_XOR_WriteProcessMemory_667b {
  strings:
    $key_667b = { 31 09 [2] 03 2b [2] 05 1e [2] 2b 1e [2] 14 02 }

  condition:
    any of them
}