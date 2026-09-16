rule TTP_XOR_WriteProcessMemory_ff35 {
  strings:
    $key_ff35 = { a8 47 [2] 9a 65 [2] 9c 50 [2] b2 50 [2] 8d 4c }

  condition:
    any of them
}