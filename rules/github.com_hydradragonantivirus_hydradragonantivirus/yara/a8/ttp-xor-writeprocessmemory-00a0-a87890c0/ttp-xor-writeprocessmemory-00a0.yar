rule TTP_XOR_WriteProcessMemory_00a0 {
  strings:
    $key_00a0 = { 57 d2 [2] 65 f0 [2] 63 c5 [2] 4d c5 [2] 72 d9 }

  condition:
    any of them
}