rule TTP_XOR_WriteProcessMemory_fee6 {
  strings:
    $key_fee6 = { a9 94 [2] 9b b6 [2] 9d 83 [2] b3 83 [2] 8c 9f }

  condition:
    any of them
}