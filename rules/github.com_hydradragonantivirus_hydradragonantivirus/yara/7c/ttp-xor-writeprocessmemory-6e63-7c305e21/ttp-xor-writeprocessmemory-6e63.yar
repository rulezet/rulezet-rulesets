rule TTP_XOR_WriteProcessMemory_6e63 {
  strings:
    $key_6e63 = { 39 11 [2] 0b 33 [2] 0d 06 [2] 23 06 [2] 1c 1a }

  condition:
    any of them
}