rule TTP_XOR_WriteProcessMemory_1482 {
  strings:
    $key_1482 = { 43 f0 [2] 71 d2 [2] 77 e7 [2] 59 e7 [2] 66 fb }

  condition:
    any of them
}