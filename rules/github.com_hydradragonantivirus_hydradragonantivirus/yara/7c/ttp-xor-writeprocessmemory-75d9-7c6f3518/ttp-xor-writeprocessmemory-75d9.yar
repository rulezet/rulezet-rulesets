rule TTP_XOR_WriteProcessMemory_75d9 {
  strings:
    $key_75d9 = { 22 ab [2] 10 89 [2] 16 bc [2] 38 bc [2] 07 a0 }

  condition:
    any of them
}