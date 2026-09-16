rule TTP_XOR_WriteProcessMemory_37d5 {
  strings:
    $key_37d5 = { 60 a7 [2] 52 85 [2] 54 b0 [2] 7a b0 [2] 45 ac }

  condition:
    any of them
}