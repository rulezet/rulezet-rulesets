rule TTP_XOR_WriteProcessMemory_c672 {
  strings:
    $key_c672 = { 91 00 [2] a3 22 [2] a5 17 [2] 8b 17 [2] b4 0b }

  condition:
    any of them
}