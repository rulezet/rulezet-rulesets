rule TTP_XOR_WriteProcessMemory_e2d6 {
  strings:
    $key_e2d6 = { b5 a4 [2] 87 86 [2] 81 b3 [2] af b3 [2] 90 af }

  condition:
    any of them
}