rule TTP_XOR_WriteProcessMemory_fa29 {
  strings:
    $key_fa29 = { ad 5b [2] 9f 79 [2] 99 4c [2] b7 4c [2] 88 50 }

  condition:
    any of them
}