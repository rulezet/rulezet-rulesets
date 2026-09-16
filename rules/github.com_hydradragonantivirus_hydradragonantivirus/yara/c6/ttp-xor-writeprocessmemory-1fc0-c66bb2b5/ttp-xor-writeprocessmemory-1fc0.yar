rule TTP_XOR_WriteProcessMemory_1fc0 {
  strings:
    $key_1fc0 = { 48 b2 [2] 7a 90 [2] 7c a5 [2] 52 a5 [2] 6d b9 }

  condition:
    any of them
}