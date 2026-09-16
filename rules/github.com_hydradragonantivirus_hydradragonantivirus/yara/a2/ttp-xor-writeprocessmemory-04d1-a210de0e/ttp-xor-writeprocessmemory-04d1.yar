rule TTP_XOR_WriteProcessMemory_04d1 {
  strings:
    $key_04d1 = { 53 a3 [2] 61 81 [2] 67 b4 [2] 49 b4 [2] 76 a8 }

  condition:
    any of them
}