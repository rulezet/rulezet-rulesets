rule TTP_XOR_WriteProcessMemory_06d5 {
  strings:
    $key_06d5 = { 51 a7 [2] 63 85 [2] 65 b0 [2] 4b b0 [2] 74 ac }

  condition:
    any of them
}