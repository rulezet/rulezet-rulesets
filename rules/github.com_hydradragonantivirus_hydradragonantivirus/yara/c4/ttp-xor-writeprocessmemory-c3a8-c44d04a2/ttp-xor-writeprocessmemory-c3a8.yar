rule TTP_XOR_WriteProcessMemory_c3a8 {
  strings:
    $key_c3a8 = { 94 da [2] a6 f8 [2] a0 cd [2] 8e cd [2] b1 d1 }

  condition:
    any of them
}