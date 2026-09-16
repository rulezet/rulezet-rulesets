rule TTP_XOR_WriteProcessMemory_14c5 {
  strings:
    $key_14c5 = { 43 b7 [2] 71 95 [2] 77 a0 [2] 59 a0 [2] 66 bc }

  condition:
    any of them
}