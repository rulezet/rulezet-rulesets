rule TTP_XOR_WriteProcessMemory_51ae {
  strings:
    $key_51ae = { 06 dc [2] 34 fe [2] 32 cb [2] 1c cb [2] 23 d7 }

  condition:
    any of them
}