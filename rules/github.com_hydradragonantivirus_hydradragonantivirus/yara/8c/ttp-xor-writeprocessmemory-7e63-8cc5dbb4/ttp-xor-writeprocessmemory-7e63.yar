rule TTP_XOR_WriteProcessMemory_7e63 {
  strings:
    $key_7e63 = { 29 11 [2] 1b 33 [2] 1d 06 [2] 33 06 [2] 0c 1a }

  condition:
    any of them
}