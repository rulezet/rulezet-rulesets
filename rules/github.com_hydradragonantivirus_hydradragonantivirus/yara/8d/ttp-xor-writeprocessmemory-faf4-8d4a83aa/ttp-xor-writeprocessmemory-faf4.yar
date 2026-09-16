rule TTP_XOR_WriteProcessMemory_faf4 {
  strings:
    $key_faf4 = { ad 86 [2] 9f a4 [2] 99 91 [2] b7 91 [2] 88 8d }

  condition:
    any of them
}