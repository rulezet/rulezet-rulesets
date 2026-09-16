rule TTP_XOR_WriteProcessMemory_55d5 {
  strings:
    $key_55d5 = { 02 a7 [2] 30 85 [2] 36 b0 [2] 18 b0 [2] 27 ac }

  condition:
    any of them
}