rule TTP_XOR_WriteProcessMemory_c8a3 {
  strings:
    $key_c8a3 = { 9f d1 [2] ad f3 [2] ab c6 [2] 85 c6 [2] ba da }

  condition:
    any of them
}