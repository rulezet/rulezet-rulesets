rule TTP_XOR_WriteProcessMemory_dd50 {
  strings:
    $key_dd50 = { 8a 22 [2] b8 00 [2] be 35 [2] 90 35 [2] af 29 }

  condition:
    any of them
}