rule TTP_XOR_WriteProcessMemory_7472 {
  strings:
    $key_7472 = { 23 00 [2] 11 22 [2] 17 17 [2] 39 17 [2] 06 0b }

  condition:
    any of them
}