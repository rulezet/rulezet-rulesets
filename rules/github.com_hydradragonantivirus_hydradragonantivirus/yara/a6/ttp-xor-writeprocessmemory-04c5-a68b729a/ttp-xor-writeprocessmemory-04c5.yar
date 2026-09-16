rule TTP_XOR_WriteProcessMemory_04c5 {
  strings:
    $key_04c5 = { 53 b7 [2] 61 95 [2] 67 a0 [2] 49 a0 [2] 76 bc }

  condition:
    any of them
}