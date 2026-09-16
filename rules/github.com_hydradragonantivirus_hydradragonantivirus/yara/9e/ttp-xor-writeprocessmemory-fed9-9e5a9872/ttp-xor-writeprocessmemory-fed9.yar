rule TTP_XOR_WriteProcessMemory_fed9 {
  strings:
    $key_fed9 = { a9 ab [2] 9b 89 [2] 9d bc [2] b3 bc [2] 8c a0 }

  condition:
    any of them
}