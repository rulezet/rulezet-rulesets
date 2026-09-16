rule TTP_XOR_WriteProcessMemory_61c0 {
  strings:
    $key_61c0 = { 36 b2 [2] 04 90 [2] 02 a5 [2] 2c a5 [2] 13 b9 }

  condition:
    any of them
}