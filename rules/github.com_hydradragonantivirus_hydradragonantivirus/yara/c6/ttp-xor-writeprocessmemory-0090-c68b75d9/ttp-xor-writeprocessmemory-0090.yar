rule TTP_XOR_WriteProcessMemory_0090 {
  strings:
    $key_0090 = { 57 e2 [2] 65 c0 [2] 63 f5 [2] 4d f5 [2] 72 e9 }

  condition:
    any of them
}