rule TTP_XOR_WriteProcessMemory_35a3 {
  strings:
    $key_35a3 = { 62 d1 [2] 50 f3 [2] 56 c6 [2] 78 c6 [2] 47 da }

  condition:
    any of them
}