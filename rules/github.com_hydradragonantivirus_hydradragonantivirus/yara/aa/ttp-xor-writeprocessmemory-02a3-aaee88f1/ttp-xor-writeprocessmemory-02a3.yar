rule TTP_XOR_WriteProcessMemory_02a3 {
  strings:
    $key_02a3 = { 55 d1 [2] 67 f3 [2] 61 c6 [2] 4f c6 [2] 70 da }

  condition:
    any of them
}