rule TTP_XOR_WriteProcessMemory_2e72 {
  strings:
    $key_2e72 = { 79 00 [2] 4b 22 [2] 4d 17 [2] 63 17 [2] 5c 0b }

  condition:
    any of them
}