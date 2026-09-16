rule TTP_XOR_WriteProcessMemory_ff06 {
  strings:
    $key_ff06 = { a8 74 [2] 9a 56 [2] 9c 63 [2] b2 63 [2] 8d 7f }

  condition:
    any of them
}