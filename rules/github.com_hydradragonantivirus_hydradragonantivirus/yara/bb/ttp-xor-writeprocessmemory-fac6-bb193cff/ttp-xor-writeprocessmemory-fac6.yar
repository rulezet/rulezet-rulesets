rule TTP_XOR_WriteProcessMemory_fac6 {
  strings:
    $key_fac6 = { ad b4 [2] 9f 96 [2] 99 a3 [2] b7 a3 [2] 88 bf }

  condition:
    any of them
}