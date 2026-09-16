rule TTP_XOR_WriteProcessMemory_04d4 {
  strings:
    $key_04d4 = { 53 a6 [2] 61 84 [2] 67 b1 [2] 49 b1 [2] 76 ad }

  condition:
    any of them
}