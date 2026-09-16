rule TTP_XOR_WriteProcessMemory_6833 {
  strings:
    $key_6833 = { 3f 41 [2] 0d 63 [2] 0b 56 [2] 25 56 [2] 1a 4a }

  condition:
    any of them
}