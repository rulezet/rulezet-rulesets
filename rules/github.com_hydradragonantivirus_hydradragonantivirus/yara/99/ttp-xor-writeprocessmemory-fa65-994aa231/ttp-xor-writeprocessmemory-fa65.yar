rule TTP_XOR_WriteProcessMemory_fa65 {
  strings:
    $key_fa65 = { ad 17 [2] 9f 35 [2] 99 00 [2] b7 00 [2] 88 1c }

  condition:
    any of them
}