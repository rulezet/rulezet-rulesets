rule TTP_XOR_WriteProcessMemory_01a3 {
  strings:
    $key_01a3 = { 56 d1 [2] 64 f3 [2] 62 c6 [2] 4c c6 [2] 73 da }

  condition:
    any of them
}