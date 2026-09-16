rule TTP_XOR_WriteProcessMemory_10c3 {
  strings:
    $key_10c3 = { 47 b1 [2] 75 93 [2] 73 a6 [2] 5d a6 [2] 62 ba }

  condition:
    any of them
}