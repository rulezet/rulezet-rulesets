rule TTP_XOR_WriteProcessMemory_d0a8 {
  strings:
    $key_d0a8 = { 87 da [2] b5 f8 [2] b3 cd [2] 9d cd [2] a2 d1 }

  condition:
    any of them
}