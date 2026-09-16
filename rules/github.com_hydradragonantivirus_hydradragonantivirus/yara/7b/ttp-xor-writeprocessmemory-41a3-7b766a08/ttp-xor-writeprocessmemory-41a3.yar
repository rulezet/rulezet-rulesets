rule TTP_XOR_WriteProcessMemory_41a3 {
  strings:
    $key_41a3 = { 16 d1 [2] 24 f3 [2] 22 c6 [2] 0c c6 [2] 33 da }

  condition:
    any of them
}