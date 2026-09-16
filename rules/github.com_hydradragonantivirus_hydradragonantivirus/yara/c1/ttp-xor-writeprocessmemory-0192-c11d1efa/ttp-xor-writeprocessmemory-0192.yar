rule TTP_XOR_WriteProcessMemory_0192 {
  strings:
    $key_0192 = { 56 e0 [2] 64 c2 [2] 62 f7 [2] 4c f7 [2] 73 eb }

  condition:
    any of them
}