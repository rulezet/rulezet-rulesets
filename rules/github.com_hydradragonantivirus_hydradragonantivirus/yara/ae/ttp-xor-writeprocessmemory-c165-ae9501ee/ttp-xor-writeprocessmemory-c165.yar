rule TTP_XOR_WriteProcessMemory_c165 {
  strings:
    $key_c165 = { 96 17 [2] a4 35 [2] a2 00 [2] 8c 00 [2] b3 1c }

  condition:
    any of them
}