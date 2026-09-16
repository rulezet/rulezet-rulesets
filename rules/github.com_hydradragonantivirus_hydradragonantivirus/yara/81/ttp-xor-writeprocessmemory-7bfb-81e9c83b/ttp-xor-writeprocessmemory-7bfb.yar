rule TTP_XOR_WriteProcessMemory_7bfb {
  strings:
    $key_7bfb = { 2c 89 [2] 1e ab [2] 18 9e [2] 36 9e [2] 09 82 }

  condition:
    any of them
}