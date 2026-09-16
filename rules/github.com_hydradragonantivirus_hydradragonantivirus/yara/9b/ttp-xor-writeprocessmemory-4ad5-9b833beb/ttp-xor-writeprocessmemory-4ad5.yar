rule TTP_XOR_WriteProcessMemory_4ad5 {
  strings:
    $key_4ad5 = { 1d a7 [2] 2f 85 [2] 29 b0 [2] 07 b0 [2] 38 ac }

  condition:
    any of them
}