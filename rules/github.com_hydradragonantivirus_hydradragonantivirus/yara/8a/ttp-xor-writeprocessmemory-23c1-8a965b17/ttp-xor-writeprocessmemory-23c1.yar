rule TTP_XOR_WriteProcessMemory_23c1 {
  strings:
    $key_23c1 = { 74 b3 [2] 46 91 [2] 40 a4 [2] 6e a4 [2] 51 b8 }

  condition:
    any of them
}