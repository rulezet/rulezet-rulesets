rule TTP_XOR_WriteProcessMemory_fee5 {
  strings:
    $key_fee5 = { a9 97 [2] 9b b5 [2] 9d 80 [2] b3 80 [2] 8c 9c }

  condition:
    any of them
}