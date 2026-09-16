rule TTP_XOR_WriteProcessMemory_1492 {
  strings:
    $key_1492 = { 43 e0 [2] 71 c2 [2] 77 f7 [2] 59 f7 [2] 66 eb }

  condition:
    any of them
}