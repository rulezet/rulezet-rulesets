rule TTP_XOR_WriteProcessMemory_28a0 {
  strings:
    $key_28a0 = { 7f d2 [2] 4d f0 [2] 4b c5 [2] 65 c5 [2] 5a d9 }

  condition:
    any of them
}