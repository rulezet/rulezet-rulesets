rule TTP_XOR_WriteProcessMemory_5f70 {
  strings:
    $key_5f70 = { 08 02 [2] 3a 20 [2] 3c 15 [2] 12 15 [2] 2d 09 }

  condition:
    any of them
}