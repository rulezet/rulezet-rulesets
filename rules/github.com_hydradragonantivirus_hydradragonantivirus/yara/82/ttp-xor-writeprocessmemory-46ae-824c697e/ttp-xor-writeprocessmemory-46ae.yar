rule TTP_XOR_WriteProcessMemory_46ae {
  strings:
    $key_46ae = { 11 dc [2] 23 fe [2] 25 cb [2] 0b cb [2] 34 d7 }

  condition:
    any of them
}