rule TTP_XOR_WriteProcessMemory_fac1 {
  strings:
    $key_fac1 = { ad b3 [2] 9f 91 [2] 99 a4 [2] b7 a4 [2] 88 b8 }

  condition:
    any of them
}