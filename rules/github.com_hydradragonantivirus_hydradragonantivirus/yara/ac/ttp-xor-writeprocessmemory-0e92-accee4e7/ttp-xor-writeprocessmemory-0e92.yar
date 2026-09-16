rule TTP_XOR_WriteProcessMemory_0e92 {
  strings:
    $key_0e92 = { 59 e0 [2] 6b c2 [2] 6d f7 [2] 43 f7 [2] 7c eb }

  condition:
    any of them
}