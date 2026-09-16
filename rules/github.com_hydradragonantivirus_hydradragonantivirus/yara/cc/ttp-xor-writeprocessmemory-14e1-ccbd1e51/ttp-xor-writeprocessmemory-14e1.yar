rule TTP_XOR_WriteProcessMemory_14e1 {
  strings:
    $key_14e1 = { 43 93 [2] 71 b1 [2] 77 84 [2] 59 84 [2] 66 98 }

  condition:
    any of them
}