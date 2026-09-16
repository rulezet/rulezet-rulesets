rule TTP_XOR_WriteProcessMemory_ff05 {
  strings:
    $key_ff05 = { a8 77 [2] 9a 55 [2] 9c 60 [2] b2 60 [2] 8d 7c }

  condition:
    any of them
}