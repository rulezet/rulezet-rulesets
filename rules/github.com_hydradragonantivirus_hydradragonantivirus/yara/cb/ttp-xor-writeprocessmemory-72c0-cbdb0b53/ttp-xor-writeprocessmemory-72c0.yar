rule TTP_XOR_WriteProcessMemory_72c0 {
  strings:
    $key_72c0 = { 25 b2 [2] 17 90 [2] 11 a5 [2] 3f a5 [2] 00 b9 }

  condition:
    any of them
}