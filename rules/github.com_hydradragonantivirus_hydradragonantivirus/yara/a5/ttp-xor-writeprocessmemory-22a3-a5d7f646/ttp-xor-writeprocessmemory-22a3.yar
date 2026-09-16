rule TTP_XOR_WriteProcessMemory_22a3 {
  strings:
    $key_22a3 = { 75 d1 [2] 47 f3 [2] 41 c6 [2] 6f c6 [2] 50 da }

  condition:
    any of them
}