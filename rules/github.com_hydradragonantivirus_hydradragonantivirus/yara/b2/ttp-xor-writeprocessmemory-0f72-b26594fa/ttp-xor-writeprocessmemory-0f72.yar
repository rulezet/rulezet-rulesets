rule TTP_XOR_WriteProcessMemory_0f72 {
  strings:
    $key_0f72 = { 58 00 [2] 6a 22 [2] 6c 17 [2] 42 17 [2] 7d 0b }

  condition:
    any of them
}