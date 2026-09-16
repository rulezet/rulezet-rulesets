rule TTP_XOR_WriteProcessMemory_606c {
  strings:
    $key_606c = { 37 1e [2] 05 3c [2] 03 09 [2] 2d 09 [2] 12 15 }

  condition:
    any of them
}