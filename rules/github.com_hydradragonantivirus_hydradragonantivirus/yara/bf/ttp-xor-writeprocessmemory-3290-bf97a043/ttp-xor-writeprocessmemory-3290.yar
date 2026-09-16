rule TTP_XOR_WriteProcessMemory_3290 {
  strings:
    $key_3290 = { 65 e2 [2] 57 c0 [2] 51 f5 [2] 7f f5 [2] 40 e9 }

  condition:
    any of them
}