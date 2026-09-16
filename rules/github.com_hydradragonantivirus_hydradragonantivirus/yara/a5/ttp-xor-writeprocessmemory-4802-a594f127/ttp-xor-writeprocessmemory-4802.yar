rule TTP_XOR_WriteProcessMemory_4802 {
  strings:
    $key_4802 = { 1f 70 [2] 2d 52 [2] 2b 67 [2] 05 67 [2] 3a 7b }

  condition:
    any of them
}