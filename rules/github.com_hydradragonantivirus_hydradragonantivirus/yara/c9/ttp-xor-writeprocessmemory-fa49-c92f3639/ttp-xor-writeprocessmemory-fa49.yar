rule TTP_XOR_WriteProcessMemory_fa49 {
  strings:
    $key_fa49 = { ad 3b [2] 9f 19 [2] 99 2c [2] b7 2c [2] 88 30 }

  condition:
    any of them
}