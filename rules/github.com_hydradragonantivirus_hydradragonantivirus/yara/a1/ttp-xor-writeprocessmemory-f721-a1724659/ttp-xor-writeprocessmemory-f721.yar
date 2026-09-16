rule TTP_XOR_WriteProcessMemory_f721 {
  strings:
    $key_f721 = { a0 53 [2] 92 71 [2] 94 44 [2] ba 44 [2] 85 58 }

  condition:
    any of them
}