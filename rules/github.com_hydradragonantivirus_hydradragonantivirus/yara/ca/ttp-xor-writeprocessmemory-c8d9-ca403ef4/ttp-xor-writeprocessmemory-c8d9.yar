rule TTP_XOR_WriteProcessMemory_c8d9 {
  strings:
    $key_c8d9 = { 9f ab [2] ad 89 [2] ab bc [2] 85 bc [2] ba a0 }

  condition:
    any of them
}