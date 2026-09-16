rule TTP_XOR_WriteProcessMemory_c730 {
  strings:
    $key_c730 = { 90 42 [2] a2 60 [2] a4 55 [2] 8a 55 [2] b5 49 }

  condition:
    any of them
}