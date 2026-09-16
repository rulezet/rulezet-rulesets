rule TTP_XOR_WriteProcessMemory_fee1 {
  strings:
    $key_fee1 = { a9 93 [2] 9b b1 [2] 9d 84 [2] b3 84 [2] 8c 98 }

  condition:
    any of them
}