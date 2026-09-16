rule TTP_XOR_WriteProcessMemory_4e70 {
  strings:
    $key_4e70 = { 19 02 [2] 2b 20 [2] 2d 15 [2] 03 15 [2] 3c 09 }

  condition:
    any of them
}