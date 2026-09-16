rule TTP_XOR_WriteProcessMemory_07a3 {
  strings:
    $key_07a3 = { 50 d1 [2] 62 f3 [2] 64 c6 [2] 4a c6 [2] 75 da }

  condition:
    any of them
}