rule TTP_XOR_WriteProcessMemory_5f5c {
  strings:
    $key_5f5c = { 08 2e [2] 3a 0c [2] 3c 39 [2] 12 39 [2] 2d 25 }

  condition:
    any of them
}