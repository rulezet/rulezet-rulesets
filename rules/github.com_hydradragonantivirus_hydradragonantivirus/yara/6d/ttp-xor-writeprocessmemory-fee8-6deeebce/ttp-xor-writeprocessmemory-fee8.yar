rule TTP_XOR_WriteProcessMemory_fee8 {
  strings:
    $key_fee8 = { a9 9a [2] 9b b8 [2] 9d 8d [2] b3 8d [2] 8c 91 }

  condition:
    any of them
}