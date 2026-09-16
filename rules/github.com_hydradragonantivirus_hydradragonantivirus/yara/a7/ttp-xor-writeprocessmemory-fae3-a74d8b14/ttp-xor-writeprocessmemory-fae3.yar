rule TTP_XOR_WriteProcessMemory_fae3 {
  strings:
    $key_fae3 = { ad 91 [2] 9f b3 [2] 99 86 [2] b7 86 [2] 88 9a }

  condition:
    any of them
}