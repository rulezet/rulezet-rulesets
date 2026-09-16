rule TTP_XOR_WriteProcessMemory_1b66 {
  strings:
    $key_1b66 = { 4c 14 [2] 7e 36 [2] 78 03 [2] 56 03 [2] 69 1f }

  condition:
    any of them
}