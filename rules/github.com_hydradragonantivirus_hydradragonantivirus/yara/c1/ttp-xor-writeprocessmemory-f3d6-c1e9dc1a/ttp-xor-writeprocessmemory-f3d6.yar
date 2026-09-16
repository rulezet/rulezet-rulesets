rule TTP_XOR_WriteProcessMemory_f3d6 {
  strings:
    $key_f3d6 = { a4 a4 [2] 96 86 [2] 90 b3 [2] be b3 [2] 81 af }

  condition:
    any of them
}