rule TTP_XOR_WriteProcessMemory_f69b {
  strings:
    $key_f69b = { a1 e9 [2] 93 cb [2] 95 fe [2] bb fe [2] 84 e2 }

  condition:
    any of them
}