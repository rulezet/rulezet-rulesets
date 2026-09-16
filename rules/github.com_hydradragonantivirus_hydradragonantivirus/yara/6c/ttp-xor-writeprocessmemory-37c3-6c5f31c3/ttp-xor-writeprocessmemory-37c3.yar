rule TTP_XOR_WriteProcessMemory_37c3 {
  strings:
    $key_37c3 = { 60 b1 [2] 52 93 [2] 54 a6 [2] 7a a6 [2] 45 ba }

  condition:
    any of them
}