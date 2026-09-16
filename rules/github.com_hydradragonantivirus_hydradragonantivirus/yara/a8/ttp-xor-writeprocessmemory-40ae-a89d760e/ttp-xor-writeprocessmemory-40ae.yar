rule TTP_XOR_WriteProcessMemory_40ae {
  strings:
    $key_40ae = { 17 dc [2] 25 fe [2] 23 cb [2] 0d cb [2] 32 d7 }

  condition:
    any of them
}