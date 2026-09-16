rule TTP_XOR_WriteProcessMemory_c179 {
  strings:
    $key_c179 = { 96 0b [2] a4 29 [2] a2 1c [2] 8c 1c [2] b3 00 }

  condition:
    any of them
}