rule TTP_XOR_WriteProcessMemory_117b {
  strings:
    $key_117b = { 46 09 [2] 74 2b [2] 72 1e [2] 5c 1e [2] 63 02 }

  condition:
    any of them
}