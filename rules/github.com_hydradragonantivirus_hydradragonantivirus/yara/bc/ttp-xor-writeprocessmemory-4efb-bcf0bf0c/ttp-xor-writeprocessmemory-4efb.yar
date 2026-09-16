rule TTP_XOR_WriteProcessMemory_4efb {
  strings:
    $key_4efb = { 19 89 [2] 2b ab [2] 2d 9e [2] 03 9e [2] 3c 82 }

  condition:
    any of them
}