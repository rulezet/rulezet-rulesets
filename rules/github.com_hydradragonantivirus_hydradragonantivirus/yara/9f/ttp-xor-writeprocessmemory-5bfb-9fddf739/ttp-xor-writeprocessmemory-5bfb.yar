rule TTP_XOR_WriteProcessMemory_5bfb {
  strings:
    $key_5bfb = { 0c 89 [2] 3e ab [2] 38 9e [2] 16 9e [2] 29 82 }

  condition:
    any of them
}