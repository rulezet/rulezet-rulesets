rule TTP_XOR_WriteProcessMemory_faf7 {
  strings:
    $key_faf7 = { ad 85 [2] 9f a7 [2] 99 92 [2] b7 92 [2] 88 8e }

  condition:
    any of them
}