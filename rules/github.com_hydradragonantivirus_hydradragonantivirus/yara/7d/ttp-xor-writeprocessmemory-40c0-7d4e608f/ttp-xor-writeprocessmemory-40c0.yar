rule TTP_XOR_WriteProcessMemory_40c0 {
  strings:
    $key_40c0 = { 17 b2 [2] 25 90 [2] 23 a5 [2] 0d a5 [2] 32 b9 }

  condition:
    any of them
}