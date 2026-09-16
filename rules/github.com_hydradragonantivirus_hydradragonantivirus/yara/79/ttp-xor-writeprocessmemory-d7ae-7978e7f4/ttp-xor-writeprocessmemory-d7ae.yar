rule TTP_XOR_WriteProcessMemory_d7ae {
  strings:
    $key_d7ae = { 80 dc [2] b2 fe [2] b4 cb [2] 9a cb [2] a5 d7 }

  condition:
    any of them
}