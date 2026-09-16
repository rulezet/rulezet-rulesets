rule TTP_XOR_WriteProcessMemory_0072 {
  strings:
    $key_0072 = { 57 00 [2] 65 22 [2] 63 17 [2] 4d 17 [2] 72 0b }

  condition:
    any of them
}