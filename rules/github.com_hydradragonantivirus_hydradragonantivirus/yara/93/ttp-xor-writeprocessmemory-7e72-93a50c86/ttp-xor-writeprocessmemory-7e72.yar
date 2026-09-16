rule TTP_XOR_WriteProcessMemory_7e72 {
  strings:
    $key_7e72 = { 29 00 [2] 1b 22 [2] 1d 17 [2] 33 17 [2] 0c 0b }

  condition:
    any of them
}