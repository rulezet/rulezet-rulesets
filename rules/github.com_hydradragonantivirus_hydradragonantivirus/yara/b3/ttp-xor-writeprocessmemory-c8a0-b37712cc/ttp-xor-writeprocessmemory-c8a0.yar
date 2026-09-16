rule TTP_XOR_WriteProcessMemory_c8a0 {
  strings:
    $key_c8a0 = { 9f d2 [2] ad f0 [2] ab c5 [2] 85 c5 [2] ba d9 }

  condition:
    any of them
}