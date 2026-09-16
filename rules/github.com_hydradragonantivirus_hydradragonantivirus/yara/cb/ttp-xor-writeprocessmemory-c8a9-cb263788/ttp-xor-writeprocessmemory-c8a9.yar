rule TTP_XOR_WriteProcessMemory_c8a9 {
  strings:
    $key_c8a9 = { 9f db [2] ad f9 [2] ab cc [2] 85 cc [2] ba d0 }

  condition:
    any of them
}