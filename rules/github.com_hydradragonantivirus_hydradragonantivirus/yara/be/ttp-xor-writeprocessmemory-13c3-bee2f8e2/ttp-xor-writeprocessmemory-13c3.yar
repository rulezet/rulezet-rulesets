rule TTP_XOR_WriteProcessMemory_13c3 {
  strings:
    $key_13c3 = { 44 b1 [2] 76 93 [2] 70 a6 [2] 5e a6 [2] 61 ba }

  condition:
    any of them
}