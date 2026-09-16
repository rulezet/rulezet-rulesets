rule TTP_XOR_WriteProcessMemory_e7d5 {
  strings:
    $key_e7d5 = { b0 a7 [2] 82 85 [2] 84 b0 [2] aa b0 [2] 95 ac }

  condition:
    any of them
}