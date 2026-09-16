rule TTP_XOR_WriteProcessMemory_23d9 {
  strings:
    $key_23d9 = { 74 ab [2] 46 89 [2] 40 bc [2] 6e bc [2] 51 a0 }

  condition:
    any of them
}