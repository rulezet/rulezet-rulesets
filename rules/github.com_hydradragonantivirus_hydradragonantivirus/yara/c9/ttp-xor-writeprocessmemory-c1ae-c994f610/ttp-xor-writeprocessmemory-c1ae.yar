rule TTP_XOR_WriteProcessMemory_c1ae {
  strings:
    $key_c1ae = { 96 dc [2] a4 fe [2] a2 cb [2] 8c cb [2] b3 d7 }

  condition:
    any of them
}