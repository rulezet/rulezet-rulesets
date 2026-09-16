rule TTP_XOR_WriteProcessMemory_fac4 {
  strings:
    $key_fac4 = { ad b6 [2] 9f 94 [2] 99 a1 [2] b7 a1 [2] 88 bd }

  condition:
    any of them
}