rule TTP_XOR_WriteProcessMemory_67e2 {
  strings:
    $key_67e2 = { 30 90 [2] 02 b2 [2] 04 87 [2] 2a 87 [2] 15 9b }

  condition:
    any of them
}