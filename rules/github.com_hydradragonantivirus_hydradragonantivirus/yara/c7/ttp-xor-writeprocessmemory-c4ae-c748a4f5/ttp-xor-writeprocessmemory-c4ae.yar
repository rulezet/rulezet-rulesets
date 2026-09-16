rule TTP_XOR_WriteProcessMemory_c4ae {
  strings:
    $key_c4ae = { 93 dc [2] a1 fe [2] a7 cb [2] 89 cb [2] b6 d7 }

  condition:
    any of them
}