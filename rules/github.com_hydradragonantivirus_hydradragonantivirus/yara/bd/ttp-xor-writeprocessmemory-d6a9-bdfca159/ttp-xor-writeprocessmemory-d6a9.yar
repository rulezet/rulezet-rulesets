rule TTP_XOR_WriteProcessMemory_d6a9 {
  strings:
    $key_d6a9 = { 81 db [2] b3 f9 [2] b5 cc [2] 9b cc [2] a4 d0 }

  condition:
    any of them
}