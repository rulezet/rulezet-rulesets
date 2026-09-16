rule TTP_XOR_WriteProcessMemory_3491 {
  strings:
    $key_3491 = { 63 e3 [2] 51 c1 [2] 57 f4 [2] 79 f4 [2] 46 e8 }

  condition:
    any of them
}