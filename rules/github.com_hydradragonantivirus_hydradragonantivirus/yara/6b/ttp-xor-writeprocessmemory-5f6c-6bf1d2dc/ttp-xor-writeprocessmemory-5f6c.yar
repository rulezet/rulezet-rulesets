rule TTP_XOR_WriteProcessMemory_5f6c {
  strings:
    $key_5f6c = { 08 1e [2] 3a 3c [2] 3c 09 [2] 12 09 [2] 2d 15 }

  condition:
    any of them
}