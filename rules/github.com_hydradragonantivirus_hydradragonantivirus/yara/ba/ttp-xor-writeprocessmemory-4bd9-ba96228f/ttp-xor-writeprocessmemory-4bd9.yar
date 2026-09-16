rule TTP_XOR_WriteProcessMemory_4bd9 {
  strings:
    $key_4bd9 = { 1c ab [2] 2e 89 [2] 28 bc [2] 06 bc [2] 39 a0 }

  condition:
    any of them
}