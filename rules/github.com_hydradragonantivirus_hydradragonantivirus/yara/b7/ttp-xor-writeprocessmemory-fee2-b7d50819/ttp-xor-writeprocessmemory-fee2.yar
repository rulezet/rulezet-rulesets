rule TTP_XOR_WriteProcessMemory_fee2 {
  strings:
    $key_fee2 = { a9 90 [2] 9b b2 [2] 9d 87 [2] b3 87 [2] 8c 9b }

  condition:
    any of them
}