rule TTP_XOR_WriteProcessMemory_c2a8 {
  strings:
    $key_c2a8 = { 95 da [2] a7 f8 [2] a1 cd [2] 8f cd [2] b0 d1 }

  condition:
    any of them
}