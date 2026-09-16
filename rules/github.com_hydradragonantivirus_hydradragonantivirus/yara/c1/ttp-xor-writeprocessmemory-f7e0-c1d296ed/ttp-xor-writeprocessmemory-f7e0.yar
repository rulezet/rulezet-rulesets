rule TTP_XOR_WriteProcessMemory_f7e0 {
  strings:
    $key_f7e0 = { a0 92 [2] 92 b0 [2] 94 85 [2] ba 85 [2] 85 99 }

  condition:
    any of them
}