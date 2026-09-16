rule TTP_XOR_WriteProcessMemory_ff03 {
  strings:
    $key_ff03 = { a8 71 [2] 9a 53 [2] 9c 66 [2] b2 66 [2] 8d 7a }

  condition:
    any of them
}