rule TTP_XOR_WriteProcessMemory_fa00 {
  strings:
    $key_fa00 = { ad 72 [2] 9f 50 [2] 99 65 [2] b7 65 [2] 88 79 }

  condition:
    any of them
}