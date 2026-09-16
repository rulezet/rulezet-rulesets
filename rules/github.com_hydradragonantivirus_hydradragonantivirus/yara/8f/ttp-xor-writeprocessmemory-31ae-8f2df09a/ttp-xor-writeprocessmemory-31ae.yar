rule TTP_XOR_WriteProcessMemory_31ae {
  strings:
    $key_31ae = { 66 dc [2] 54 fe [2] 52 cb [2] 7c cb [2] 43 d7 }

  condition:
    any of them
}