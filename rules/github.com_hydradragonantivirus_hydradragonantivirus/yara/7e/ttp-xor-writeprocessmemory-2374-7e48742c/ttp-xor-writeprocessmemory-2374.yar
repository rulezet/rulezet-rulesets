rule TTP_XOR_WriteProcessMemory_2374 {
  strings:
    $key_2374 = { 74 06 [2] 46 24 [2] 40 11 [2] 6e 11 [2] 51 0d }

  condition:
    any of them
}