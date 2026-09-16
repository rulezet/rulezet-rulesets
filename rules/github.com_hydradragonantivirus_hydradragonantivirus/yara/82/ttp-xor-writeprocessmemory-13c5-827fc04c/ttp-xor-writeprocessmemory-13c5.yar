rule TTP_XOR_WriteProcessMemory_13c5 {
  strings:
    $key_13c5 = { 44 b7 [2] 76 95 [2] 70 a0 [2] 5e a0 [2] 61 bc }

  condition:
    any of them
}