rule TTP_XOR_WriteProcessMemory_45d5 {
  strings:
    $key_45d5 = { 12 a7 [2] 20 85 [2] 26 b0 [2] 08 b0 [2] 37 ac }

  condition:
    any of them
}