rule TTP_XOR_WriteProcessMemory_4872 {
  strings:
    $key_4872 = { 1f 00 [2] 2d 22 [2] 2b 17 [2] 05 17 [2] 3a 0b }

  condition:
    any of them
}