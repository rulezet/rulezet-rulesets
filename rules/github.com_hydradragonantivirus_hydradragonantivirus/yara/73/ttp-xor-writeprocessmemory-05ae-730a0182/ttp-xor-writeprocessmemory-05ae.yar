rule TTP_XOR_WriteProcessMemory_05ae {
  strings:
    $key_05ae = { 52 dc [2] 60 fe [2] 66 cb [2] 48 cb [2] 77 d7 }

  condition:
    any of them
}