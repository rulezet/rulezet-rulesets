rule TTP_XOR_WriteProcessMemory_d0a9 {
  strings:
    $key_d0a9 = { 87 db [2] b5 f9 [2] b3 cc [2] 9d cc [2] a2 d0 }

  condition:
    any of them
}