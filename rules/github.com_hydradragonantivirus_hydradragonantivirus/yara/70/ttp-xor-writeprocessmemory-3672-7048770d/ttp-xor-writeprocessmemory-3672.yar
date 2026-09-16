rule TTP_XOR_WriteProcessMemory_3672 {
  strings:
    $key_3672 = { 61 00 [2] 53 22 [2] 55 17 [2] 7b 17 [2] 44 0b }

  condition:
    any of them
}