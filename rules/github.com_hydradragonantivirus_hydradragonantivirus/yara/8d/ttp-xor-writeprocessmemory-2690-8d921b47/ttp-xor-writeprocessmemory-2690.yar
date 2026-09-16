rule TTP_XOR_WriteProcessMemory_2690 {
  strings:
    $key_2690 = { 71 e2 [2] 43 c0 [2] 45 f5 [2] 6b f5 [2] 54 e9 }

  condition:
    any of them
}