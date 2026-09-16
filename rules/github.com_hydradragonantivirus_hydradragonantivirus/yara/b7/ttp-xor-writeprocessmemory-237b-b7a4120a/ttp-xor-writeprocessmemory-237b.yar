rule TTP_XOR_WriteProcessMemory_237b {
  strings:
    $key_237b = { 74 09 [2] 46 2b [2] 40 1e [2] 6e 1e [2] 51 02 }

  condition:
    any of them
}