rule TTP_XOR_WriteProcessMemory_54f0 {
  strings:
    $key_54f0 = { 03 82 [2] 31 a0 [2] 37 95 [2] 19 95 [2] 26 89 }

  condition:
    any of them
}