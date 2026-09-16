rule TTP_XOR_WriteProcessMemory_ff40 {
  strings:
    $key_ff40 = { a8 32 [2] 9a 10 [2] 9c 25 [2] b2 25 [2] 8d 39 }

  condition:
    any of them
}