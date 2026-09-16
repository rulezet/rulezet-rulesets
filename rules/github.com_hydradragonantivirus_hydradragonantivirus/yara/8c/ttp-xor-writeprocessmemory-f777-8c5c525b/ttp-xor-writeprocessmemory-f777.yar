rule TTP_XOR_WriteProcessMemory_f777 {
  strings:
    $key_f777 = { a0 05 [2] 92 27 [2] 94 12 [2] ba 12 [2] 85 0e }

  condition:
    any of them
}