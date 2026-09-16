rule TTP_XOR_WriteProcessMemory_6d90 {
  strings:
    $key_6d90 = { 3a e2 [2] 08 c0 [2] 0e f5 [2] 20 f5 [2] 1f e9 }

  condition:
    any of them
}