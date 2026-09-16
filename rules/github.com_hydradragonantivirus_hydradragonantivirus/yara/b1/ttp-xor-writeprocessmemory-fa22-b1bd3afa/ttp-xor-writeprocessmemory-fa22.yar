rule TTP_XOR_WriteProcessMemory_fa22 {
  strings:
    $key_fa22 = { ad 50 [2] 9f 72 [2] 99 47 [2] b7 47 [2] 88 5b }

  condition:
    any of them
}