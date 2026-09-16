rule TTP_XOR_WriteProcessMemory_ff51 {
  strings:
    $key_ff51 = { a8 23 [2] 9a 01 [2] 9c 34 [2] b2 34 [2] 8d 28 }

  condition:
    any of them
}