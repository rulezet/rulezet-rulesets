rule TTP_XOR_WriteProcessMemory_c4a8 {
  strings:
    $key_c4a8 = { 93 da [2] a1 f8 [2] a7 cd [2] 89 cd [2] b6 d1 }

  condition:
    any of them
}