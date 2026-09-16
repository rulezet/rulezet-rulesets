rule TTP_XOR_WriteProcessMemory_5f29 {
  strings:
    $key_5f29 = { 08 5b [2] 3a 79 [2] 3c 4c [2] 12 4c [2] 2d 50 }

  condition:
    any of them
}