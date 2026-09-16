rule TTP_XOR_WriteProcessMemory_faf3 {
  strings:
    $key_faf3 = { ad 81 [2] 9f a3 [2] 99 96 [2] b7 96 [2] 88 8a }

  condition:
    any of them
}