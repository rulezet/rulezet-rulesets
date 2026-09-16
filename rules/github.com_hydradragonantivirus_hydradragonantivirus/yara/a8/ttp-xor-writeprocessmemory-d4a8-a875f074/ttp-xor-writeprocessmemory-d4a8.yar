rule TTP_XOR_WriteProcessMemory_d4a8 {
  strings:
    $key_d4a8 = { 83 da [2] b1 f8 [2] b7 cd [2] 99 cd [2] a6 d1 }

  condition:
    any of them
}