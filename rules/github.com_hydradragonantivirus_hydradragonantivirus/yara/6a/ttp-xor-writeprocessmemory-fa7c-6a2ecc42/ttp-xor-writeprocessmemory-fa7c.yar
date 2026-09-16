rule TTP_XOR_WriteProcessMemory_fa7c {
  strings:
    $key_fa7c = { ad 0e [2] 9f 2c [2] 99 19 [2] b7 19 [2] 88 05 }

  condition:
    any of them
}