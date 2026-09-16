rule TTP_XOR_WriteProcessMemory_14c0 {
  strings:
    $key_14c0 = { 43 b2 [2] 71 90 [2] 77 a5 [2] 59 a5 [2] 66 b9 }

  condition:
    any of them
}