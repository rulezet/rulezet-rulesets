rule TTP_XOR_WriteProcessMemory_3e90 {
  strings:
    $key_3e90 = { 69 e2 [2] 5b c0 [2] 5d f5 [2] 73 f5 [2] 4c e9 }

  condition:
    any of them
}