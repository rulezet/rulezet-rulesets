rule TTP_XOR_WriteProcessMemory_61c3 {
  strings:
    $key_61c3 = { 36 b1 [2] 04 93 [2] 02 a6 [2] 2c a6 [2] 13 ba }

  condition:
    any of them
}