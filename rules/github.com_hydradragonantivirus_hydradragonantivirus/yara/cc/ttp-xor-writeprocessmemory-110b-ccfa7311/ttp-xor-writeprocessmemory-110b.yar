rule TTP_XOR_WriteProcessMemory_110b {
  strings:
    $key_110b = { 46 79 [2] 74 5b [2] 72 6e [2] 5c 6e [2] 63 72 }

  condition:
    any of them
}