rule TTP_XOR_WriteProcessMemory_3f72 {
  strings:
    $key_3f72 = { 68 00 [2] 5a 22 [2] 5c 17 [2] 72 17 [2] 4d 0b }

  condition:
    any of them
}