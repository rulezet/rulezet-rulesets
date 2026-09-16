rule TTP_XOR_WriteProcessMemory_32d1 {
  strings:
    $key_32d1 = { 65 a3 [2] 57 81 [2] 51 b4 [2] 7f b4 [2] 40 a8 }

  condition:
    any of them
}