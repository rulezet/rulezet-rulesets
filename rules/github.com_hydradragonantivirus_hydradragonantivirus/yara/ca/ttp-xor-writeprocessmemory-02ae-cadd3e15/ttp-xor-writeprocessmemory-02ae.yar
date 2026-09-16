rule TTP_XOR_WriteProcessMemory_02ae {
  strings:
    $key_02ae = { 55 dc [2] 67 fe [2] 61 cb [2] 4f cb [2] 70 d7 }

  condition:
    any of them
}