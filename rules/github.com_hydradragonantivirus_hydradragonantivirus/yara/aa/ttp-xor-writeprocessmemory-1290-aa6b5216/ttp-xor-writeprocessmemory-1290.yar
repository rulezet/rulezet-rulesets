rule TTP_XOR_WriteProcessMemory_1290 {
  strings:
    $key_1290 = { 45 e2 [2] 77 c0 [2] 71 f5 [2] 5f f5 [2] 60 e9 }

  condition:
    any of them
}