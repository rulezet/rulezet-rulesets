rule TTP_XOR_WriteProcessMemory_f6d5 {
  strings:
    $key_f6d5 = { a1 a7 [2] 93 85 [2] 95 b0 [2] bb b0 [2] 84 ac }

  condition:
    any of them
}