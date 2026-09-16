rule TTP_XOR_WriteProcessMemory_fa43 {
  strings:
    $key_fa43 = { ad 31 [2] 9f 13 [2] 99 26 [2] b7 26 [2] 88 3a }

  condition:
    any of them
}