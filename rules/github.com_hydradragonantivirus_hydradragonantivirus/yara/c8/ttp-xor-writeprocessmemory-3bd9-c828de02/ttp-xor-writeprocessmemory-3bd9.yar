rule TTP_XOR_WriteProcessMemory_3bd9 {
  strings:
    $key_3bd9 = { 6c ab [2] 5e 89 [2] 58 bc [2] 76 bc [2] 49 a0 }

  condition:
    any of them
}