rule TTP_XOR_WriteProcessMemory_15c3 {
  strings:
    $key_15c3 = { 42 b1 [2] 70 93 [2] 76 a6 [2] 58 a6 [2] 67 ba }

  condition:
    any of them
}