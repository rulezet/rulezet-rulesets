rule TTP_XOR_WriteProcessMemory_61d5 {
  strings:
    $key_61d5 = { 36 a7 [2] 04 85 [2] 02 b0 [2] 2c b0 [2] 13 ac }

  condition:
    any of them
}