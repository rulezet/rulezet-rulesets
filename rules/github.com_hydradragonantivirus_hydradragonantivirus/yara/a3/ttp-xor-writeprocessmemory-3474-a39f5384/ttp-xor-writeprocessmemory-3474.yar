rule TTP_XOR_WriteProcessMemory_3474 {
  strings:
    $key_3474 = { 63 06 [2] 51 24 [2] 57 11 [2] 79 11 [2] 46 0d }

  condition:
    any of them
}