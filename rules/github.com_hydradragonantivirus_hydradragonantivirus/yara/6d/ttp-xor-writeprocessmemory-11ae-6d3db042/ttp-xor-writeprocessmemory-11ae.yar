rule TTP_XOR_WriteProcessMemory_11ae {
  strings:
    $key_11ae = { 46 dc [2] 74 fe [2] 72 cb [2] 5c cb [2] 63 d7 }

  condition:
    any of them
}