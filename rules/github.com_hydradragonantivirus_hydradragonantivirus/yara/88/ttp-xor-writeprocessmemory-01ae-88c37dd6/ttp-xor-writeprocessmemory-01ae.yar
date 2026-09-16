rule TTP_XOR_WriteProcessMemory_01ae {
  strings:
    $key_01ae = { 56 dc [2] 64 fe [2] 62 cb [2] 4c cb [2] 73 d7 }

  condition:
    any of them
}