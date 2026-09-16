rule TTP_XOR_WriteProcessMemory_fae5 {
  strings:
    $key_fae5 = { ad 97 [2] 9f b5 [2] 99 80 [2] b7 80 [2] 88 9c }

  condition:
    any of them
}