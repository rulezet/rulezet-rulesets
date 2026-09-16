rule TTP_XOR_WriteProcessMemory_1474 {
  strings:
    $key_1474 = { 43 06 [2] 71 24 [2] 77 11 [2] 59 11 [2] 66 0d }

  condition:
    any of them
}