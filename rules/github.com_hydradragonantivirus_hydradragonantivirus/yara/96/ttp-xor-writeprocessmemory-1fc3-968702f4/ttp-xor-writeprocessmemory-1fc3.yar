rule TTP_XOR_WriteProcessMemory_1fc3 {
  strings:
    $key_1fc3 = { 48 b1 [2] 7a 93 [2] 7c a6 [2] 52 a6 [2] 6d ba }

  condition:
    any of them
}