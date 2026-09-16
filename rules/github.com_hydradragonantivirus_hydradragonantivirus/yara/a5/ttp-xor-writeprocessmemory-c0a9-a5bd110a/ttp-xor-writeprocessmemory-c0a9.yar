rule TTP_XOR_WriteProcessMemory_c0a9 {
  strings:
    $key_c0a9 = { 97 db [2] a5 f9 [2] a3 cc [2] 8d cc [2] b2 d0 }

  condition:
    any of them
}