rule TTP_XOR_WriteProcessMemory_0e72 {
  strings:
    $key_0e72 = { 59 00 [2] 6b 22 [2] 6d 17 [2] 43 17 [2] 7c 0b }

  condition:
    any of them
}