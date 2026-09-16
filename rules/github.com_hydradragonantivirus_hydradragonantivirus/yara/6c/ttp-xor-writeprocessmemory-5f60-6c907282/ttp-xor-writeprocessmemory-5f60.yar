rule TTP_XOR_WriteProcessMemory_5f60 {
  strings:
    $key_5f60 = { 08 12 [2] 3a 30 [2] 3c 05 [2] 12 05 [2] 2d 19 }

  condition:
    any of them
}