rule TTP_XOR_WriteProcessMemory_f7ae {
  strings:
    $key_f7ae = { a0 dc [2] 92 fe [2] 94 cb [2] ba cb [2] 85 d7 }

  condition:
    any of them
}