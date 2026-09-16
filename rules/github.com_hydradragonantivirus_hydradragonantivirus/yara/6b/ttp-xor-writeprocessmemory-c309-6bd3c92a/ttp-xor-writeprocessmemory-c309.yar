rule TTP_XOR_WriteProcessMemory_c309 {
  strings:
    $key_c309 = { 94 7b [2] a6 59 [2] a0 6c [2] 8e 6c [2] b1 70 }

  condition:
    any of them
}