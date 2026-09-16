rule TTP_XOR_WriteProcessMemory_44d5 {
  strings:
    $key_44d5 = { 13 a7 [2] 21 85 [2] 27 b0 [2] 09 b0 [2] 36 ac }

  condition:
    any of them
}