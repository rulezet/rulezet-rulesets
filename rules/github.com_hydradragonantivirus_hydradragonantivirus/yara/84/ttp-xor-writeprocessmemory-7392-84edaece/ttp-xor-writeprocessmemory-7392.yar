rule TTP_XOR_WriteProcessMemory_7392 {
  strings:
    $key_7392 = { 24 e0 [2] 16 c2 [2] 10 f7 [2] 3e f7 [2] 01 eb }

  condition:
    any of them
}