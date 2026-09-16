rule TTP_XOR_WriteProcessMemory_56d5 {
  strings:
    $key_56d5 = { 01 a7 [2] 33 85 [2] 35 b0 [2] 1b b0 [2] 24 ac }

  condition:
    any of them
}