rule TTP_XOR_WriteProcessMemory_d6a8 {
  strings:
    $key_d6a8 = { 81 da [2] b3 f8 [2] b5 cd [2] 9b cd [2] a4 d1 }

  condition:
    any of them
}