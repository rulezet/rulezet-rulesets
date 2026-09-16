rule TTP_XOR_WriteProcessMemory_fee0 {
  strings:
    $key_fee0 = { a9 92 [2] 9b b0 [2] 9d 85 [2] b3 85 [2] 8c 99 }

  condition:
    any of them
}