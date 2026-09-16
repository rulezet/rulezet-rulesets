rule TTP_XOR_WriteProcessMemory_fa13 {
  strings:
    $key_fa13 = { ad 61 [2] 9f 43 [2] 99 76 [2] b7 76 [2] 88 6a }

  condition:
    any of them
}