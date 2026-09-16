rule TTP_XOR_WriteProcessMemory_4e72 {
  strings:
    $key_4e72 = { 19 00 [2] 2b 22 [2] 2d 17 [2] 03 17 [2] 3c 0b }

  condition:
    any of them
}