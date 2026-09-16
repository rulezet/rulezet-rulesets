rule TTP_XOR_WriteProcessMemory_f8d6 {
  strings:
    $key_f8d6 = { af a4 [2] 9d 86 [2] 9b b3 [2] b5 b3 [2] 8a af }

  condition:
    any of them
}