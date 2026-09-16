rule TTP_XOR_WriteProcessMemory_fa63 {
  strings:
    $key_fa63 = { ad 11 [2] 9f 33 [2] 99 06 [2] b7 06 [2] 88 1a }

  condition:
    any of them
}