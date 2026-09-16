rule TTP_XOR_WriteProcessMemory_72ae {
  strings:
    $key_72ae = { 25 dc [2] 17 fe [2] 11 cb [2] 3f cb [2] 00 d7 }

  condition:
    any of them
}