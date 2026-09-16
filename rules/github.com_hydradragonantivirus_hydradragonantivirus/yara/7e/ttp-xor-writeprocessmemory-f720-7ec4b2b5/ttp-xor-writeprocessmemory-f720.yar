rule TTP_XOR_WriteProcessMemory_f720 {
  strings:
    $key_f720 = { a0 52 [2] 92 70 [2] 94 45 [2] ba 45 [2] 85 59 }

  condition:
    any of them
}