rule TTP_XOR_WriteProcessMemory_2f72 {
  strings:
    $key_2f72 = { 78 00 [2] 4a 22 [2] 4c 17 [2] 62 17 [2] 5d 0b }

  condition:
    any of them
}