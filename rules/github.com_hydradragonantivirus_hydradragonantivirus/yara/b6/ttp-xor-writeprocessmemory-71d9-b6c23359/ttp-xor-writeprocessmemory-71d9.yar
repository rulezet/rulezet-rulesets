rule TTP_XOR_WriteProcessMemory_71d9 {
  strings:
    $key_71d9 = { 26 ab [2] 14 89 [2] 12 bc [2] 3c bc [2] 03 a0 }

  condition:
    any of them
}