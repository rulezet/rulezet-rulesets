rule TTP_XOR_WriteProcessMemory_63c3 {
  strings:
    $key_63c3 = { 34 b1 [2] 06 93 [2] 00 a6 [2] 2e a6 [2] 11 ba }

  condition:
    any of them
}