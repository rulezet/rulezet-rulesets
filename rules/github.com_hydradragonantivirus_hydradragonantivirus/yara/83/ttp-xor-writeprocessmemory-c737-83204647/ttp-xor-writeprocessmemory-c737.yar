rule TTP_XOR_WriteProcessMemory_c737 {
  strings:
    $key_c737 = { 90 45 [2] a2 67 [2] a4 52 [2] 8a 52 [2] b5 4e }

  condition:
    any of them
}