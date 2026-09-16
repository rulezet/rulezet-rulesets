rule TTP_XOR_WriteProcessMemory_c671 {
  strings:
    $key_c671 = { 91 03 [2] a3 21 [2] a5 14 [2] 8b 14 [2] b4 08 }

  condition:
    any of them
}