rule TTP_XOR_WriteProcessMemory_fef7 {
  strings:
    $key_fef7 = { a9 85 [2] 9b a7 [2] 9d 92 [2] b3 92 [2] 8c 8e }

  condition:
    any of them
}