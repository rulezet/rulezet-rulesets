rule TTP_XOR_WriteProcessMemory_fae6 {
  strings:
    $key_fae6 = { ad 94 [2] 9f b6 [2] 99 83 [2] b7 83 [2] 88 9f }

  condition:
    any of them
}