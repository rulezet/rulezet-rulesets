rule TTP_XOR_WriteProcessMemory_fa70 {
  strings:
    $key_fa70 = { ad 02 [2] 9f 20 [2] 99 15 [2] b7 15 [2] 88 09 }

  condition:
    any of them
}