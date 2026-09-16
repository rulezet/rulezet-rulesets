rule TTP_XOR_WriteProcessMemory_1491 {
  strings:
    $key_1491 = { 43 e3 [2] 71 c1 [2] 77 f4 [2] 59 f4 [2] 66 e8 }

  condition:
    any of them
}