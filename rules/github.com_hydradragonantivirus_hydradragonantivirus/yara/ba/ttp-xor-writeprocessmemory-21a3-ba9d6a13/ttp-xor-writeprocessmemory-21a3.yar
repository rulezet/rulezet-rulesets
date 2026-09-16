rule TTP_XOR_WriteProcessMemory_21a3 {
  strings:
    $key_21a3 = { 76 d1 [2] 44 f3 [2] 42 c6 [2] 6c c6 [2] 53 da }

  condition:
    any of them
}