rule TTP_XOR_WriteProcessMemory_61d9 {
  strings:
    $key_61d9 = { 36 ab [2] 04 89 [2] 02 bc [2] 2c bc [2] 13 a0 }

  condition:
    any of them
}