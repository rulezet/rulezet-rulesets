rule TTP_XOR_WriteProcessMemory_cc46 {
  strings:
    $key_cc46 = { 9b 34 [2] a9 16 [2] af 23 [2] 81 23 [2] be 3f }

  condition:
    any of them
}