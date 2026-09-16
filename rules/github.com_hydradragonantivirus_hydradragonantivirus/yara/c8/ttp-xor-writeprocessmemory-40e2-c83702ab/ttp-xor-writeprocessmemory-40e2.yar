rule TTP_XOR_WriteProcessMemory_40e2 {
  strings:
    $key_40e2 = { 17 90 [2] 25 b2 [2] 23 87 [2] 0d 87 [2] 32 9b }

  condition:
    any of them
}