rule TTP_XOR_WriteProcessMemory_3432 {
  strings:
    $key_3432 = { 63 40 [2] 51 62 [2] 57 57 [2] 79 57 [2] 46 4b }

  condition:
    any of them
}