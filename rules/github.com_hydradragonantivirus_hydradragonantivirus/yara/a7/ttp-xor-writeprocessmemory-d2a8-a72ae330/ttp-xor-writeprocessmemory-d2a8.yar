rule TTP_XOR_WriteProcessMemory_d2a8 {
  strings:
    $key_d2a8 = { 85 da [2] b7 f8 [2] b1 cd [2] 9f cd [2] a0 d1 }

  condition:
    any of them
}