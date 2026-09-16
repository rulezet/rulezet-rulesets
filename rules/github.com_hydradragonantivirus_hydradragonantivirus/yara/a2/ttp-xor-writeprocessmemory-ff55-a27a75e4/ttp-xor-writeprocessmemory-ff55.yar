rule TTP_XOR_WriteProcessMemory_ff55 {
  strings:
    $key_ff55 = { a8 27 [2] 9a 05 [2] 9c 30 [2] b2 30 [2] 8d 2c }

  condition:
    any of them
}