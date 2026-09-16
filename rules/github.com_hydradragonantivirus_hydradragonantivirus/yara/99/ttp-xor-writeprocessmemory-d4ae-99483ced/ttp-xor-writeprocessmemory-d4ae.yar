rule TTP_XOR_WriteProcessMemory_d4ae {
  strings:
    $key_d4ae = { 83 dc [2] b1 fe [2] b7 cb [2] 99 cb [2] a6 d7 }

  condition:
    any of them
}