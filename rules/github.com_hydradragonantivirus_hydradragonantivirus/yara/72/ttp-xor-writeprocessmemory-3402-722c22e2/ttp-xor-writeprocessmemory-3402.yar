rule TTP_XOR_WriteProcessMemory_3402 {
  strings:
    $key_3402 = { 63 70 [2] 51 52 [2] 57 67 [2] 79 67 [2] 46 7b }

  condition:
    any of them
}