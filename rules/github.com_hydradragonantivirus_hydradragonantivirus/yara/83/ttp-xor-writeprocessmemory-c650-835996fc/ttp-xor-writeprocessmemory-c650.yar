rule TTP_XOR_WriteProcessMemory_c650 {
  strings:
    $key_c650 = { 91 22 [2] a3 00 [2] a5 35 [2] 8b 35 [2] b4 29 }

  condition:
    any of them
}