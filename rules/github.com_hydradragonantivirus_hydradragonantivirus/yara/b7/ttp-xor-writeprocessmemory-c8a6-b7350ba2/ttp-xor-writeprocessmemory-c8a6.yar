rule TTP_XOR_WriteProcessMemory_c8a6 {
  strings:
    $key_c8a6 = { 9f d4 [2] ad f6 [2] ab c3 [2] 85 c3 [2] ba df }

  condition:
    any of them
}