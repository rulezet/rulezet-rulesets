rule TTP_XOR_WriteProcessMemory_1864 {
  strings:
    $key_1864 = { 4f 16 [2] 7d 34 [2] 7b 01 [2] 55 01 [2] 6a 1d }

  condition:
    any of them
}