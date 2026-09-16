rule TTP_XOR_WriteProcessMemory_01c3 {
  strings:
    $key_01c3 = { 56 b1 [2] 64 93 [2] 62 a6 [2] 4c a6 [2] 73 ba }

  condition:
    any of them
}