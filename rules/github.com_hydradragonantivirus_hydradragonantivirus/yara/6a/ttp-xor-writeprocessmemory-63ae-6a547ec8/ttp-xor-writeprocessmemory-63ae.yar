rule TTP_XOR_WriteProcessMemory_63ae {
  strings:
    $key_63ae = { 34 dc [2] 06 fe [2] 00 cb [2] 2e cb [2] 11 d7 }

  condition:
    any of them
}