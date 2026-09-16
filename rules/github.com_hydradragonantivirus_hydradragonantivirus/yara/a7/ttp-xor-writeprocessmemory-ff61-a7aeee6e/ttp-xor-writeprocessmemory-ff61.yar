rule TTP_XOR_WriteProcessMemory_ff61 {
  strings:
    $key_ff61 = { a8 13 [2] 9a 31 [2] 9c 04 [2] b2 04 [2] 8d 18 }

  condition:
    any of them
}