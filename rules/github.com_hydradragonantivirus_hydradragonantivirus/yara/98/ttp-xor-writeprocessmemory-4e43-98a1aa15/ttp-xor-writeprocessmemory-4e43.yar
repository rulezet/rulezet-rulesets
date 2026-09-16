rule TTP_XOR_WriteProcessMemory_4e43 {
  strings:
    $key_4e43 = { 19 31 [2] 2b 13 [2] 2d 26 [2] 03 26 [2] 3c 3a }

  condition:
    any of them
}