rule TTP_XOR_WriteProcessMemory_14e2 {
  strings:
    $key_14e2 = { 43 90 [2] 71 b2 [2] 77 87 [2] 59 87 [2] 66 9b }

  condition:
    any of them
}