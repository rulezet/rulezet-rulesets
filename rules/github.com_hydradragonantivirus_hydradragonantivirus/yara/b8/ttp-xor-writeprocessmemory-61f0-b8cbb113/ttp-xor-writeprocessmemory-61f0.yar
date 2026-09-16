rule TTP_XOR_WriteProcessMemory_61f0 {
  strings:
    $key_61f0 = { 36 82 [2] 04 a0 [2] 02 95 [2] 2c 95 [2] 13 89 }

  condition:
    any of them
}