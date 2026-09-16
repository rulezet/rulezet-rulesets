rule TTP_XOR_WriteProcessMemory_74d9 {
  strings:
    $key_74d9 = { 23 ab [2] 11 89 [2] 17 bc [2] 39 bc [2] 06 a0 }

  condition:
    any of them
}