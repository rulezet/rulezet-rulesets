rule TTP_XOR_WriteProcessMemory_c032 {
  strings:
    $key_c032 = { 97 40 [2] a5 62 [2] a3 57 [2] 8d 57 [2] b2 4b }

  condition:
    any of them
}