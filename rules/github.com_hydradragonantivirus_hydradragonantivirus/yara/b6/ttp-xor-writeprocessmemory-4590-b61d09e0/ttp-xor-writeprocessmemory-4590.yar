rule TTP_XOR_WriteProcessMemory_4590 {
  strings:
    $key_4590 = { 12 e2 [2] 20 c0 [2] 26 f5 [2] 08 f5 [2] 37 e9 }

  condition:
    any of them
}