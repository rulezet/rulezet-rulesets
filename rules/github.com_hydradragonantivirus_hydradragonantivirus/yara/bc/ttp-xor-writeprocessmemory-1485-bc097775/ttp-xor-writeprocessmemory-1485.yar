rule TTP_XOR_WriteProcessMemory_1485 {
  strings:
    $key_1485 = { 43 f7 [2] 71 d5 [2] 77 e0 [2] 59 e0 [2] 66 fc }

  condition:
    any of them
}