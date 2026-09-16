rule TTP_XOR_WriteProcessMemory_0190 {
  strings:
    $key_0190 = { 56 e2 [2] 64 c0 [2] 62 f5 [2] 4c f5 [2] 73 e9 }

  condition:
    any of them
}