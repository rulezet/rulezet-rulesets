rule TTP_XOR_WriteProcessMemory_115b {
  strings:
    $key_115b = { 46 29 [2] 74 0b [2] 72 3e [2] 5c 3e [2] 63 22 }

  condition:
    any of them
}