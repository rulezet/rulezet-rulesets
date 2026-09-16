rule TTP_XOR_WriteProcessMemory_33c3 {
  strings:
    $key_33c3 = { 64 b1 [2] 56 93 [2] 50 a6 [2] 7e a6 [2] 41 ba }

  condition:
    any of them
}