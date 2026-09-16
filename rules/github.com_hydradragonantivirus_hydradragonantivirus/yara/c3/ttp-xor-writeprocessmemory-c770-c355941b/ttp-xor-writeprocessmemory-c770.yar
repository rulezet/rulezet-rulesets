rule TTP_XOR_WriteProcessMemory_c770 {
  strings:
    $key_c770 = { 90 02 [2] a2 20 [2] a4 15 [2] 8a 15 [2] b5 09 }

  condition:
    any of them
}