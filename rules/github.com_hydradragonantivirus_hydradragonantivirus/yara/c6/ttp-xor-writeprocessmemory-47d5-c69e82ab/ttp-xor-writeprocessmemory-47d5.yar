rule TTP_XOR_WriteProcessMemory_47d5 {
  strings:
    $key_47d5 = { 10 a7 [2] 22 85 [2] 24 b0 [2] 0a b0 [2] 35 ac }

  condition:
    any of them
}