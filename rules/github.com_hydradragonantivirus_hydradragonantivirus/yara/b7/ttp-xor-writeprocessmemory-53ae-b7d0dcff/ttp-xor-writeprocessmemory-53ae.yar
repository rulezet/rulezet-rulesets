rule TTP_XOR_WriteProcessMemory_53ae {
  strings:
    $key_53ae = { 04 dc [2] 36 fe [2] 30 cb [2] 1e cb [2] 21 d7 }

  condition:
    any of them
}