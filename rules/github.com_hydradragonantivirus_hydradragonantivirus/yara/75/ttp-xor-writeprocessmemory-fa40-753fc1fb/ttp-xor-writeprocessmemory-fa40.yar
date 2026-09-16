rule TTP_XOR_WriteProcessMemory_fa40 {
  strings:
    $key_fa40 = { ad 32 [2] 9f 10 [2] 99 25 [2] b7 25 [2] 88 39 }

  condition:
    any of them
}