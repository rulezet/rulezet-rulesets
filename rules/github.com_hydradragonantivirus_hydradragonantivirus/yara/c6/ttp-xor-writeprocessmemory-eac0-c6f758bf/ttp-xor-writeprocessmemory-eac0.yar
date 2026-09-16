rule TTP_XOR_WriteProcessMemory_eac0 {
  strings:
    $key_eac0 = { bd b2 [2] 8f 90 [2] 89 a5 [2] a7 a5 [2] 98 b9 }

  condition:
    any of them
}