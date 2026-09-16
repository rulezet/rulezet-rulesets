rule TTP_XOR_WriteProcessMemory_efc6 {
  strings:
    $key_efc6 = { b8 b4 [2] 8a 96 [2] 8c a3 [2] a2 a3 [2] 9d bf }

  condition:
    any of them
}