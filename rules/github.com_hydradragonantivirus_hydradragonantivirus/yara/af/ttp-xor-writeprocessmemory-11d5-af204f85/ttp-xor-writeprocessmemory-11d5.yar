rule TTP_XOR_WriteProcessMemory_11d5 {
  strings:
    $key_11d5 = { 46 a7 [2] 74 85 [2] 72 b0 [2] 5c b0 [2] 63 ac }

  condition:
    any of them
}