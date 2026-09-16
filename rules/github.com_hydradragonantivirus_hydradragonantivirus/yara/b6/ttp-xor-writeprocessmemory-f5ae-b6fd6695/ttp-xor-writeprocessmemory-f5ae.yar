rule TTP_XOR_WriteProcessMemory_f5ae {
  strings:
    $key_f5ae = { a2 dc [2] 90 fe [2] 96 cb [2] b8 cb [2] 87 d7 }

  condition:
    any of them
}