rule TTP_XOR_WriteProcessMemory_fae1 {
  strings:
    $key_fae1 = { ad 93 [2] 9f b1 [2] 99 84 [2] b7 84 [2] 88 98 }

  condition:
    any of them
}