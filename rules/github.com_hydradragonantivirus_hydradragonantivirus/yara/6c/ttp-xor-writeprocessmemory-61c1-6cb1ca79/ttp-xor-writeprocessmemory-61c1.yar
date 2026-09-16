rule TTP_XOR_WriteProcessMemory_61c1 {
  strings:
    $key_61c1 = { 36 b3 [2] 04 91 [2] 02 a4 [2] 2c a4 [2] 13 b8 }

  condition:
    any of them
}