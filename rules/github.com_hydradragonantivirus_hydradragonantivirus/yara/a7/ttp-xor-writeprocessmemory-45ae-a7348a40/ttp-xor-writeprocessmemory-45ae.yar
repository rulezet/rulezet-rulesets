rule TTP_XOR_WriteProcessMemory_45ae {
  strings:
    $key_45ae = { 12 dc [2] 20 fe [2] 26 cb [2] 08 cb [2] 37 d7 }

  condition:
    any of them
}