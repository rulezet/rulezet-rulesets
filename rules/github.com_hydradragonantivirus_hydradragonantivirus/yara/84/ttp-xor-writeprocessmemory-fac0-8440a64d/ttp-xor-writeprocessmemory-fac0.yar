rule TTP_XOR_WriteProcessMemory_fac0 {
  strings:
    $key_fac0 = { ad b2 [2] 9f 90 [2] 99 a5 [2] b7 a5 [2] 88 b9 }

  condition:
    any of them
}