rule TTP_XOR_WriteProcessMemory_c773 {
  strings:
    $key_c773 = { 90 01 [2] a2 23 [2] a4 16 [2] 8a 16 [2] b5 0a }

  condition:
    any of them
}