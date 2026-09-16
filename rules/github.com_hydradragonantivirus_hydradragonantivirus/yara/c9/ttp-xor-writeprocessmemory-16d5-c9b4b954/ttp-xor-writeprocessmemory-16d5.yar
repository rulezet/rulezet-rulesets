rule TTP_XOR_WriteProcessMemory_16d5 {
  strings:
    $key_16d5 = { 41 a7 [2] 73 85 [2] 75 b0 [2] 5b b0 [2] 64 ac }

  condition:
    any of them
}