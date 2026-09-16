rule TTP_XOR_WriteProcessMemory_f7b9 {
  strings:
    $key_f7b9 = { a0 cb [2] 92 e9 [2] 94 dc [2] ba dc [2] 85 c0 }

  condition:
    any of them
}