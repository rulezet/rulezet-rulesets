rule TTP_XOR_WriteProcessMemory_d4a9 {
  strings:
    $key_d4a9 = { 83 db [2] b1 f9 [2] b7 cc [2] 99 cc [2] a6 d0 }

  condition:
    any of them
}