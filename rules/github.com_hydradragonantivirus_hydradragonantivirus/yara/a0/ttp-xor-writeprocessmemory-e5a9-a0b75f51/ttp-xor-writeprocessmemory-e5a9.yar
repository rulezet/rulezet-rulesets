rule TTP_XOR_WriteProcessMemory_e5a9 {
  strings:
    $key_e5a9 = { b2 db [2] 80 f9 [2] 86 cc [2] a8 cc [2] 97 d0 }

  condition:
    any of them
}