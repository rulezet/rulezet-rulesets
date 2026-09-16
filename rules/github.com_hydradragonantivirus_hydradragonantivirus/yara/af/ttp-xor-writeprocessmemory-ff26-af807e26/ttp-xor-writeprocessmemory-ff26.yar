rule TTP_XOR_WriteProcessMemory_ff26 {
  strings:
    $key_ff26 = { a8 54 [2] 9a 76 [2] 9c 43 [2] b2 43 [2] 8d 5f }

  condition:
    any of them
}