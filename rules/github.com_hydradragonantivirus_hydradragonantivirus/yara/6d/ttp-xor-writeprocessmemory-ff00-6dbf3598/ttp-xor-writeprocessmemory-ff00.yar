rule TTP_XOR_WriteProcessMemory_ff00 {
  strings:
    $key_ff00 = { a8 72 [2] 9a 50 [2] 9c 65 [2] b2 65 [2] 8d 79 }

  condition:
    any of them
}