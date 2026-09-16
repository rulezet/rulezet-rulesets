rule TTP_XOR_WriteProcessMemory_74ae {
  strings:
    $key_74ae = { 23 dc [2] 11 fe [2] 17 cb [2] 39 cb [2] 06 d7 }

  condition:
    any of them
}