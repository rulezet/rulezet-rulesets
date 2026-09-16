rule TTP_XOR_WriteProcessMemory_ff60 {
  strings:
    $key_ff60 = { a8 12 [2] 9a 30 [2] 9c 05 [2] b2 05 [2] 8d 19 }

  condition:
    any of them
}