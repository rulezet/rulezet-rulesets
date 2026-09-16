rule TTP_XOR_WriteProcessMemory_ff30 {
  strings:
    $key_ff30 = { a8 42 [2] 9a 60 [2] 9c 55 [2] b2 55 [2] 8d 49 }

  condition:
    any of them
}