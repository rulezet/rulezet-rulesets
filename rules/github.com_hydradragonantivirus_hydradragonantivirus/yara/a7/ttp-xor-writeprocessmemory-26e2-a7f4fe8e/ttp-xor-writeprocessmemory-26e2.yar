rule TTP_XOR_WriteProcessMemory_26e2 {
  strings:
    $key_26e2 = { 71 90 [2] 43 b2 [2] 45 87 [2] 6b 87 [2] 54 9b }

  condition:
    any of them
}