rule TTP_XOR_WriteProcessMemory_fee4 {
  strings:
    $key_fee4 = { a9 96 [2] 9b b4 [2] 9d 81 [2] b3 81 [2] 8c 9d }

  condition:
    any of them
}