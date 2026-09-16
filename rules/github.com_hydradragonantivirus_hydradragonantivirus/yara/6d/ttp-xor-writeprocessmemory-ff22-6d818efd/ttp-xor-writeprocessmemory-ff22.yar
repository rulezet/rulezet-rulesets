rule TTP_XOR_WriteProcessMemory_ff22 {
  strings:
    $key_ff22 = { a8 50 [2] 9a 72 [2] 9c 47 [2] b2 47 [2] 8d 5b }

  condition:
    any of them
}