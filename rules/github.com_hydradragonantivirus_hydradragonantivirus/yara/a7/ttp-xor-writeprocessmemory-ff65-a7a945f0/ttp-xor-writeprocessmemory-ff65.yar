rule TTP_XOR_WriteProcessMemory_ff65 {
  strings:
    $key_ff65 = { a8 17 [2] 9a 35 [2] 9c 00 [2] b2 00 [2] 8d 1c }

  condition:
    any of them
}