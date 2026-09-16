rule TTP_XOR_WriteProcessMemory_61e0 {
  strings:
    $key_61e0 = { 36 92 [2] 04 b0 [2] 02 85 [2] 2c 85 [2] 13 99 }

  condition:
    any of them
}