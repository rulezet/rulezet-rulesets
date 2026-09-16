rule TTP_XOR_WriteProcessMemory_f791 {
  strings:
    $key_f791 = { a0 e3 [2] 92 c1 [2] 94 f4 [2] ba f4 [2] 85 e8 }

  condition:
    any of them
}