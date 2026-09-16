rule TTP_XOR_WriteProcessMemory_d201 {
  strings:
    $key_d201 = { 85 73 [2] b7 51 [2] b1 64 [2] 9f 64 [2] a0 78 }

  condition:
    any of them
}