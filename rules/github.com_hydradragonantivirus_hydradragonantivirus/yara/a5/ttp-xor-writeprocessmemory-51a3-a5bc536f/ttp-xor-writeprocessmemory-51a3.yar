rule TTP_XOR_WriteProcessMemory_51a3 {
  strings:
    $key_51a3 = { 06 d1 [2] 34 f3 [2] 32 c6 [2] 1c c6 [2] 23 da }

  condition:
    any of them
}