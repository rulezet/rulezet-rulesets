rule TTP_XOR_WriteProcessMemory_1fc6 {
  strings:
    $key_1fc6 = { 48 b4 [2] 7a 96 [2] 7c a3 [2] 52 a3 [2] 6d bf }

  condition:
    any of them
}