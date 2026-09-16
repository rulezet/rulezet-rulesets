rule TTP_XOR_WriteProcessMemory_e2d1 {
  strings:
    $key_e2d1 = { b5 a3 [2] 87 81 [2] 81 b4 [2] af b4 [2] 90 a8 }

  condition:
    any of them
}