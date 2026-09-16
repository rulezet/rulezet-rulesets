rule TTP_XOR_WriteProcessMemory_43d5 {
  strings:
    $key_43d5 = { 14 a7 [2] 26 85 [2] 20 b0 [2] 0e b0 [2] 31 ac }

  condition:
    any of them
}