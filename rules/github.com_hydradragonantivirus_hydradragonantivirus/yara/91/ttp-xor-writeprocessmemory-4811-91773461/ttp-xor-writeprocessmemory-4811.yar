rule TTP_XOR_WriteProcessMemory_4811 {
  strings:
    $key_4811 = { 1f 63 [2] 2d 41 [2] 2b 74 [2] 05 74 [2] 3a 68 }

  condition:
    any of them
}