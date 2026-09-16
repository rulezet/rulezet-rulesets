rule TTP_XOR_WriteProcessMemory_52d5 {
  strings:
    $key_52d5 = { 05 a7 [2] 37 85 [2] 31 b0 [2] 1f b0 [2] 20 ac }

  condition:
    any of them
}