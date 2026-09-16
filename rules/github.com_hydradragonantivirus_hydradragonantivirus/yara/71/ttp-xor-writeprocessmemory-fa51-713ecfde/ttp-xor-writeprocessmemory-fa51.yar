rule TTP_XOR_WriteProcessMemory_fa51 {
  strings:
    $key_fa51 = { ad 23 [2] 9f 01 [2] 99 34 [2] b7 34 [2] 88 28 }

  condition:
    any of them
}