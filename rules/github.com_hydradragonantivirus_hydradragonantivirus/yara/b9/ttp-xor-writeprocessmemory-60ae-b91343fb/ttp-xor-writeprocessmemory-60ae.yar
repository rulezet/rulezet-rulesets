rule TTP_XOR_WriteProcessMemory_60ae {
  strings:
    $key_60ae = { 37 dc [2] 05 fe [2] 03 cb [2] 2d cb [2] 12 d7 }

  condition:
    any of them
}