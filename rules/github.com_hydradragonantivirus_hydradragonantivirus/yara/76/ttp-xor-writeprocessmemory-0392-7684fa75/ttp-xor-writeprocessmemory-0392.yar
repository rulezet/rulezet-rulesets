rule TTP_XOR_WriteProcessMemory_0392 {
  strings:
    $key_0392 = { 54 e0 [2] 66 c2 [2] 60 f7 [2] 4e f7 [2] 71 eb }

  condition:
    any of them
}