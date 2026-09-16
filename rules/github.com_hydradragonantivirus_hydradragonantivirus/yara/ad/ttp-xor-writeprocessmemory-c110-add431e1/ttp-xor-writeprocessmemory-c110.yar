rule TTP_XOR_WriteProcessMemory_c110 {
  strings:
    $key_c110 = { 96 62 [2] a4 40 [2] a2 75 [2] 8c 75 [2] b3 69 }

  condition:
    any of them
}