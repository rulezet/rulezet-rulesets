rule TTP_XOR_WriteProcessMemory_ff46 {
  strings:
    $key_ff46 = { a8 34 [2] 9a 16 [2] 9c 23 [2] b2 23 [2] 8d 3f }

  condition:
    any of them
}