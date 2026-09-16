rule TTP_XOR_WriteProcessMemory_dc95 {
  strings:
    $key_dc95 = { 8b e7 [2] b9 c5 [2] bf f0 [2] 91 f0 [2] ae ec }

  condition:
    any of them
}