rule TTP_XOR_WriteProcessMemory_6e43 {
  strings:
    $key_6e43 = { 39 31 [2] 0b 13 [2] 0d 26 [2] 23 26 [2] 1c 3a }

  condition:
    any of them
}