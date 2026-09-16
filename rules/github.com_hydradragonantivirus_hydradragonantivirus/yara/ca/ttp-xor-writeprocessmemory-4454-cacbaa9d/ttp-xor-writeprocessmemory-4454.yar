rule TTP_XOR_WriteProcessMemory_4454 {
  strings:
    $key_4454 = { 13 26 [2] 21 04 [2] 27 31 [2] 09 31 [2] 36 2d }

  condition:
    any of them
}