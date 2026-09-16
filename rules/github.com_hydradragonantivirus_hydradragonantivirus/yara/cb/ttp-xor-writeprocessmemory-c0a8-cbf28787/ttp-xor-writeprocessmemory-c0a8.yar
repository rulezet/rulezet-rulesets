rule TTP_XOR_WriteProcessMemory_c0a8 {
  strings:
    $key_c0a8 = { 97 da [2] a5 f8 [2] a3 cd [2] 8d cd [2] b2 d1 }

  condition:
    any of them
}