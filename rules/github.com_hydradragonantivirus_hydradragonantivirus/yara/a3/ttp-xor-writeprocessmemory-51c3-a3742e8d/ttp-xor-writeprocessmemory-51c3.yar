rule TTP_XOR_WriteProcessMemory_51c3 {
  strings:
    $key_51c3 = { 06 b1 [2] 34 93 [2] 32 a6 [2] 1c a6 [2] 23 ba }

  condition:
    any of them
}