rule TTP_XOR_WriteProcessMemory_34d1 {
  strings:
    $key_34d1 = { 63 a3 [2] 51 81 [2] 57 b4 [2] 79 b4 [2] 46 a8 }

  condition:
    any of them
}