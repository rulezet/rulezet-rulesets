rule TTP_XOR_WriteProcessMemory_5f39 {
  strings:
    $key_5f39 = { 08 4b [2] 3a 69 [2] 3c 5c [2] 12 5c [2] 2d 40 }

  condition:
    any of them
}