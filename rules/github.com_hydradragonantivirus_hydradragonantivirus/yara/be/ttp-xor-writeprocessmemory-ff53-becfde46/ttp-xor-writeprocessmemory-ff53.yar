rule TTP_XOR_WriteProcessMemory_ff53 {
  strings:
    $key_ff53 = { a8 21 [2] 9a 03 [2] 9c 36 [2] b2 36 [2] 8d 2a }

  condition:
    any of them
}