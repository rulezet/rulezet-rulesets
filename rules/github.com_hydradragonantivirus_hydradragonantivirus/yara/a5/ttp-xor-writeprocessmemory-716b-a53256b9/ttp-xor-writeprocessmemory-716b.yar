rule TTP_XOR_WriteProcessMemory_716b {
  strings:
    $key_716b = { 26 19 [2] 14 3b [2] 12 0e [2] 3c 0e [2] 03 12 }

  condition:
    any of them
}