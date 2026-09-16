rule TTP_XOR_WriteProcessMemory_2fc6 {
  strings:
    $key_2fc6 = { 78 b4 [2] 4a 96 [2] 4c a3 [2] 62 a3 [2] 5d bf }

  condition:
    any of them
}