rule TTP_XOR_WriteProcessMemory_61a3 {
  strings:
    $key_61a3 = { 36 d1 [2] 04 f3 [2] 02 c6 [2] 2c c6 [2] 13 da }

  condition:
    any of them
}