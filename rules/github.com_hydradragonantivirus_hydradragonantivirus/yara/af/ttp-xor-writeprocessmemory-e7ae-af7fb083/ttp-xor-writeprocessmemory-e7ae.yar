rule TTP_XOR_WriteProcessMemory_e7ae {
  strings:
    $key_e7ae = { b0 dc [2] 82 fe [2] 84 cb [2] aa cb [2] 95 d7 }

  condition:
    any of them
}