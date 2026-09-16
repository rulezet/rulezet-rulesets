rule TTP_XOR_WriteProcessMemory_f706 {
  strings:
    $key_f706 = { a0 74 [2] 92 56 [2] 94 63 [2] ba 63 [2] 85 7f }

  condition:
    any of them
}