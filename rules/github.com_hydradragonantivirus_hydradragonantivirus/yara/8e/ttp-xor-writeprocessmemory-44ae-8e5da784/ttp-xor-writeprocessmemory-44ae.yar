rule TTP_XOR_WriteProcessMemory_44ae {
  strings:
    $key_44ae = { 13 dc [2] 21 fe [2] 27 cb [2] 09 cb [2] 36 d7 }

  condition:
    any of them
}