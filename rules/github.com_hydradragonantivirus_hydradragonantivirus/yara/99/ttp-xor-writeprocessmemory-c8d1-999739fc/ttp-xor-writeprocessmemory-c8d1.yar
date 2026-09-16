rule TTP_XOR_WriteProcessMemory_c8d1 {
  strings:
    $key_c8d1 = { 9f a3 [2] ad 81 [2] ab b4 [2] 85 b4 [2] ba a8 }

  condition:
    any of them
}