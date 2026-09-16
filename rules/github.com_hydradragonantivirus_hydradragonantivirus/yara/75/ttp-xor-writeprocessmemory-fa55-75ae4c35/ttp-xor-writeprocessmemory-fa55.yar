rule TTP_XOR_WriteProcessMemory_fa55 {
  strings:
    $key_fa55 = { ad 27 [2] 9f 05 [2] 99 30 [2] b7 30 [2] 88 2c }

  condition:
    any of them
}