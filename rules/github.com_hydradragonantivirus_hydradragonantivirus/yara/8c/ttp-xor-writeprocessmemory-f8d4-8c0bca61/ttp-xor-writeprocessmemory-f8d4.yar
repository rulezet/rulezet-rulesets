rule TTP_XOR_WriteProcessMemory_f8d4 {
  strings:
    $key_f8d4 = { af a6 [2] 9d 84 [2] 9b b1 [2] b5 b1 [2] 8a ad }

  condition:
    any of them
}