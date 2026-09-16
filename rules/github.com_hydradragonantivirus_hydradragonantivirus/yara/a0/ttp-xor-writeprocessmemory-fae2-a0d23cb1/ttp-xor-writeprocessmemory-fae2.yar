rule TTP_XOR_WriteProcessMemory_fae2 {
  strings:
    $key_fae2 = { ad 90 [2] 9f b2 [2] 99 87 [2] b7 87 [2] 88 9b }

  condition:
    any of them
}