rule TTP_XOR_WriteProcessMemory_d1ae {
  strings:
    $key_d1ae = { 86 dc [2] b4 fe [2] b2 cb [2] 9c cb [2] a3 d7 }

  condition:
    any of them
}