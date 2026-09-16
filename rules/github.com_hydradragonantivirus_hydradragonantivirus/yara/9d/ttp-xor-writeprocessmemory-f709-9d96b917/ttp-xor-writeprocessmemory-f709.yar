rule TTP_XOR_WriteProcessMemory_f709 {
  strings:
    $key_f709 = { a0 7b [2] 92 59 [2] 94 6c [2] ba 6c [2] 85 70 }

  condition:
    any of them
}