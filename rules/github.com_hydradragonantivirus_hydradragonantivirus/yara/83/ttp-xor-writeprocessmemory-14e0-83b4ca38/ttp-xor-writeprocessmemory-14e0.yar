rule TTP_XOR_WriteProcessMemory_14e0 {
  strings:
    $key_14e0 = { 43 92 [2] 71 b0 [2] 77 85 [2] 59 85 [2] 66 99 }

  condition:
    any of them
}