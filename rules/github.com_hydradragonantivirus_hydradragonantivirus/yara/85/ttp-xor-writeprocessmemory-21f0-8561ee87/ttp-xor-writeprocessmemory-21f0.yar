rule TTP_XOR_WriteProcessMemory_21f0 {
  strings:
    $key_21f0 = { 76 82 [2] 44 a0 [2] 42 95 [2] 6c 95 [2] 53 89 }

  condition:
    any of them
}