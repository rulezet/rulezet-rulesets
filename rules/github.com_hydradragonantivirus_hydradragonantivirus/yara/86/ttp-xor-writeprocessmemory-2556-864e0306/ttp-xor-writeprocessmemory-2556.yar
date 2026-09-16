rule TTP_XOR_WriteProcessMemory_2556 {
  strings:
    $key_2556 = { 72 24 [2] 40 06 [2] 46 33 [2] 68 33 [2] 57 2f }

  condition:
    any of them
}