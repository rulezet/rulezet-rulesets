rule TTP_XOR_WriteProcessMemory_0bfb {
  strings:
    $key_0bfb = { 5c 89 [2] 6e ab [2] 68 9e [2] 46 9e [2] 79 82 }

  condition:
    any of them
}