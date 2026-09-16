rule TTP_XOR_WriteProcessMemory_fa75 {
  strings:
    $key_fa75 = { ad 07 [2] 9f 25 [2] 99 10 [2] b7 10 [2] 88 0c }

  condition:
    any of them
}