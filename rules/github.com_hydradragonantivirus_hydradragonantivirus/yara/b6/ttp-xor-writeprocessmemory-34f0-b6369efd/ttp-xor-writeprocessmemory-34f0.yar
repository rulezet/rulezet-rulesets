rule TTP_XOR_WriteProcessMemory_34f0 {
  strings:
    $key_34f0 = { 63 82 [2] 51 a0 [2] 57 95 [2] 79 95 [2] 46 89 }

  condition:
    any of them
}