rule TTP_XOR_WriteProcessMemory_fa50 {
  strings:
    $key_fa50 = { ad 22 [2] 9f 00 [2] 99 35 [2] b7 35 [2] 88 29 }

  condition:
    any of them
}