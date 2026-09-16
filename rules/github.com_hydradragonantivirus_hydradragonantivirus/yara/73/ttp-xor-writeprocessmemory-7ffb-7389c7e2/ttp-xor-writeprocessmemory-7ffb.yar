rule TTP_XOR_WriteProcessMemory_7ffb {
  strings:
    $key_7ffb = { 28 89 [2] 1a ab [2] 1c 9e [2] 32 9e [2] 0d 82 }

  condition:
    any of them
}