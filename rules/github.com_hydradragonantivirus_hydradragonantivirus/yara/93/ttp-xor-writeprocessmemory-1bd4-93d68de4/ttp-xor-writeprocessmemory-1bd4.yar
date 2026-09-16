rule TTP_XOR_WriteProcessMemory_1bd4 {
  strings:
    $key_1bd4 = { 4c a6 [2] 7e 84 [2] 78 b1 [2] 56 b1 [2] 69 ad }

  condition:
    any of them
}