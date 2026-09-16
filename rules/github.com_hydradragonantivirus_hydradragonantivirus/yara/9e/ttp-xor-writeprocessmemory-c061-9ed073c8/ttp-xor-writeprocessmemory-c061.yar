rule TTP_XOR_WriteProcessMemory_c061 {
  strings:
    $key_c061 = { 97 13 [2] a5 31 [2] a3 04 [2] 8d 04 [2] b2 18 }

  condition:
    any of them
}