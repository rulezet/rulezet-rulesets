rule TTP_XOR_WriteProcessMemory_3391 {
  strings:
    $key_3391 = { 64 e3 [2] 56 c1 [2] 50 f4 [2] 7e f4 [2] 41 e8 }

  condition:
    any of them
}