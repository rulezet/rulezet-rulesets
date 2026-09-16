rule TTP_XOR_WriteProcessMemory_25c5 {
  strings:
    $key_25c5 = { 72 b7 [2] 40 95 [2] 46 a0 [2] 68 a0 [2] 57 bc }

  condition:
    any of them
}