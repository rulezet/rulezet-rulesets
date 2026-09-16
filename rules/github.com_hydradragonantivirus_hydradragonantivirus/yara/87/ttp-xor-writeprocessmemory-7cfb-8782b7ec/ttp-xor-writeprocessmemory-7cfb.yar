rule TTP_XOR_WriteProcessMemory_7cfb {
  strings:
    $key_7cfb = { 2b 89 [2] 19 ab [2] 1f 9e [2] 31 9e [2] 0e 82 }

  condition:
    any of them
}