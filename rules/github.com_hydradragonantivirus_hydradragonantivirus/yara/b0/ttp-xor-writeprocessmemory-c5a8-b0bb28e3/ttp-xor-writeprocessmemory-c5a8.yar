rule TTP_XOR_WriteProcessMemory_c5a8 {
  strings:
    $key_c5a8 = { 92 da [2] a0 f8 [2] a6 cd [2] 88 cd [2] b7 d1 }

  condition:
    any of them
}