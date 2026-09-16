rule TTP_XOR_WriteProcessMemory_fa12 {
  strings:
    $key_fa12 = { ad 60 [2] 9f 42 [2] 99 77 [2] b7 77 [2] 88 6b }

  condition:
    any of them
}