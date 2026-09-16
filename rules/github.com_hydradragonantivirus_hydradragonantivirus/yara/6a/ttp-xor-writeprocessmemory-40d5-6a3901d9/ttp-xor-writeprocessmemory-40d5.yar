rule TTP_XOR_WriteProcessMemory_40d5 {
  strings:
    $key_40d5 = { 17 a7 [2] 25 85 [2] 23 b0 [2] 0d b0 [2] 32 ac }

  condition:
    any of them
}