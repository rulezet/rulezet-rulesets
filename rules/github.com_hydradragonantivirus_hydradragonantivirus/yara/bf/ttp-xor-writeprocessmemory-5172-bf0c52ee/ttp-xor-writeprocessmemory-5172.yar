rule TTP_XOR_WriteProcessMemory_5172 {
  strings:
    $key_5172 = { 06 00 [2] 34 22 [2] 32 17 [2] 1c 17 [2] 23 0b }

  condition:
    any of them
}