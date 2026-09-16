rule TTP_XOR_WriteProcessMemory_3454 {
  strings:
    $key_3454 = { 63 26 [2] 51 04 [2] 57 31 [2] 79 31 [2] 46 2d }

  condition:
    any of them
}