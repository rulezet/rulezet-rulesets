rule TTP_XOR_WriteProcessMemory_6e72 {
  strings:
    $key_6e72 = { 39 00 [2] 0b 22 [2] 0d 17 [2] 23 17 [2] 1c 0b }

  condition:
    any of them
}