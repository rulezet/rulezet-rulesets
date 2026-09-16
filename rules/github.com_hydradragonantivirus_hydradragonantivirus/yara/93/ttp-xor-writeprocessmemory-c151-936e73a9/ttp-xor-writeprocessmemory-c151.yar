rule TTP_XOR_WriteProcessMemory_c151 {
  strings:
    $key_c151 = { 96 23 [2] a4 01 [2] a2 34 [2] 8c 34 [2] b3 28 }

  condition:
    any of them
}