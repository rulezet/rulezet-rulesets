rule TTP_XOR_WriteProcessMemory_7491 {
  strings:
    $key_7491 = { 23 e3 [2] 11 c1 [2] 17 f4 [2] 39 f4 [2] 06 e8 }

  condition:
    any of them
}