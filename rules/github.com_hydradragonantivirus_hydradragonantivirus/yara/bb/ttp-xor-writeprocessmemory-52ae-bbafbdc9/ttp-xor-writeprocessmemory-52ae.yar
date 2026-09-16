rule TTP_XOR_WriteProcessMemory_52ae {
  strings:
    $key_52ae = { 05 dc [2] 37 fe [2] 31 cb [2] 1f cb [2] 20 d7 }

  condition:
    any of them
}