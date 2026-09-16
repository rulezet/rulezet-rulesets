rule TTP_XOR_WriteProcessMemory_6bfb {
  strings:
    $key_6bfb = { 3c 89 [2] 0e ab [2] 08 9e [2] 26 9e [2] 19 82 }

  condition:
    any of them
}