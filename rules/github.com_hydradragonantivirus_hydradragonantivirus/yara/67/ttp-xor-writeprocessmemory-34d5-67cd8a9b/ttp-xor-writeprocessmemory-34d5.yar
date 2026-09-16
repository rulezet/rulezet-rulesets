rule TTP_XOR_WriteProcessMemory_34d5 {
  strings:
    $key_34d5 = { 63 a7 [2] 51 85 [2] 57 b0 [2] 79 b0 [2] 46 ac }

  condition:
    any of them
}