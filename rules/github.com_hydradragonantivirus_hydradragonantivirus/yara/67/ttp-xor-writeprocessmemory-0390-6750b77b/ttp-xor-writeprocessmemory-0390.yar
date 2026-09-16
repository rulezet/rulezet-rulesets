rule TTP_XOR_WriteProcessMemory_0390 {
  strings:
    $key_0390 = { 54 e2 [2] 66 c0 [2] 60 f5 [2] 4e f5 [2] 71 e9 }

  condition:
    any of them
}