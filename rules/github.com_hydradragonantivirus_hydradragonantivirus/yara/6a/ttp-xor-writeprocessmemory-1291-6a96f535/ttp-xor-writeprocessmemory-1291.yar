rule TTP_XOR_WriteProcessMemory_1291 {
  strings:
    $key_1291 = { 45 e3 [2] 77 c1 [2] 71 f4 [2] 5f f4 [2] 60 e8 }

  condition:
    any of them
}