rule TTP_XOR_WriteProcessMemory_15a3 {
  strings:
    $key_15a3 = { 42 d1 [2] 70 f3 [2] 76 c6 [2] 58 c6 [2] 67 da }

  condition:
    any of them
}